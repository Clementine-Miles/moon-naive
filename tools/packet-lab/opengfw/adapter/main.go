// Offline lab adapter. This is not a production moon-naive dependency.
// The OpenGFW engine, reassembler, expression rules and analyzers are unmodified.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdIO "io"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/tcp"
	"github.com/apernet/OpenGFW/analyzer/udp"
	"github.com/apernet/OpenGFW/engine"
	gfwIO "github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type captureReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type packet struct {
	id   uint32
	data []byte
	done chan struct{}
}

func (p *packet) StreamID() uint32 { return p.id }
func (p *packet) Data() []byte     { return p.data }

type pcapIO struct {
	r                captureReader
	port             uint
	packets, skipped uint64
	flows            map[string]uint32
}

func (p *pcapIO) Register(ctx context.Context, cb gfwIO.PacketCallback) error {
	go func() {
		for {
			data, ci, err := p.r.ReadPacketData()
			if err != nil {
				cb(nil, err)
				return
			}
			if ci.CaptureLength != ci.Length {
				cb(nil, fmt.Errorf("truncated packet: %d/%d", ci.CaptureLength, ci.Length))
				return
			}
			decoded := gopacket.NewPacket(data, p.r.LinkType(), gopacket.Default)
			nl, tl := decoded.NetworkLayer(), decoded.TransportLayer()
			if nl == nil || tl == nil {
				p.skipped++
				continue
			}
			var srcPort, dstPort uint16
			var protocol string
			switch t := tl.(type) {
			case *layers.TCP:
				srcPort, dstPort, protocol = uint16(t.SrcPort), uint16(t.DstPort), "tcp"
			case *layers.UDP:
				srcPort, dstPort, protocol = uint16(t.SrcPort), uint16(t.DstPort), "udp"
			default:
				p.skipped++
				continue
			}
			if p.port != 0 && uint(srcPort) != p.port && uint(dstPort) != p.port {
				p.skipped++
				continue
			}
			src := net.JoinHostPort(nl.NetworkFlow().Src().String(), strconv.Itoa(int(srcPort)))
			dst := net.JoinHostPort(nl.NetworkFlow().Dst().String(), strconv.Itoa(int(dstPort)))
			if src > dst {
				src, dst = dst, src
			}
			key := protocol + " " + src + " " + dst
			id, ok := p.flows[key]
			if !ok {
				id = uint32(len(p.flows) + 1)
				p.flows[key] = id
			}
			ipData := append(append([]byte(nil), nl.LayerContents()...), nl.LayerPayload()...)
			pkt := &packet{id: id, data: ipData, done: make(chan struct{})}
			if !cb(pkt, nil) {
				return
			}
			// Exactly one in-flight packet: preserve capture ordering and drain the
			// worker before EOF. We never turn a simulated verdict into live I/O.
			select {
			case <-pkt.done:
				p.packets++
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
func (p *pcapIO) SetVerdict(pkt gfwIO.Packet, _ gfwIO.Verdict, _ []byte) error {
	close(pkt.(*packet).done)
	return nil
}
func (p *pcapIO) ProtectedDialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("offline adapter does not permit outbound network access")
}
func (p *pcapIO) Close() error { return nil }

type logger struct {
	mu  sync.Mutex
	out *json.Encoder
}

func (l *logger) event(kind string, info ruleset.StreamInfo, extra map[string]any) {
	v := map[string]any{"event": kind, "id": info.ID, "protocol": info.Protocol.String(), "src": info.SrcString(), "dst": info.DstString(), "props": info.Props}
	for k, x := range extra {
		v[k] = x
	}
	l.emit(v)
}
func (l *logger) emit(v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.out.Encode(v); err != nil {
		panic(err)
	}
}
func (l *logger) WorkerStart(int)                          {}
func (l *logger) WorkerStop(int)                           {}
func (l *logger) TCPStreamNew(_ int, i ruleset.StreamInfo) { l.event("new", i, nil) }
func (l *logger) TCPStreamPropUpdate(i ruleset.StreamInfo, close bool) {
	l.event("update", i, map[string]any{"closed": close})
}
func (l *logger) TCPStreamAction(i ruleset.StreamInfo, a ruleset.Action, n bool) {
	l.event("action", i, map[string]any{"action": a.String(), "no_match": n})
}
func (l *logger) UDPStreamNew(w int, i ruleset.StreamInfo)         { l.TCPStreamNew(w, i) }
func (l *logger) UDPStreamPropUpdate(i ruleset.StreamInfo, c bool) { l.TCPStreamPropUpdate(i, c) }
func (l *logger) UDPStreamAction(i ruleset.StreamInfo, a ruleset.Action, n bool) {
	l.TCPStreamAction(i, a, n)
}
func (l *logger) ModifyError(i ruleset.StreamInfo, e error) {
	l.event("modify_error", i, map[string]any{"error": e.Error()})
}
func (l *logger) AnalyzerDebugf(int64, string, string, ...any) {}
func (l *logger) AnalyzerInfof(id int64, n, f string, a ...any) {
	l.emit(map[string]any{"event": "analyzer_info", "id": id, "analyzer": n, "message": fmt.Sprintf(f, a...)})
}
func (l *logger) AnalyzerErrorf(id int64, n, f string, a ...any) {
	l.emit(map[string]any{"event": "analyzer_error", "id": id, "analyzer": n, "message": fmt.Sprintf(f, a...)})
}
func (l *logger) Log(i ruleset.StreamInfo, n string) { l.event("rule", i, map[string]any{"rule": n}) }
func (l *logger) MatchError(i ruleset.StreamInfo, n string, e error) {
	l.event("rule_error", i, map[string]any{"rule": n, "error": e.Error()})
}

func run() error {
	input := flag.String("pcap", "", "input PCAP or PCAPNG file")
	ruleFile := flag.String("rules", "", "OpenGFW YAML expression rules")
	port := flag.Uint("port", 0, "only replay TCP/UDP packets using this port; 0 means all")
	flag.Parse()
	if *input == "" || *ruleFile == "" || *port > 65535 {
		return errors.New("require -pcap and -rules; -port must be in 0..65535")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		return err
	}
	var reader captureReader
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		reader, err = pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
	} else {
		reader, err = pcapgo.NewReader(br)
	}
	if err != nil {
		return err
	}
	l := &logger{out: json.NewEncoder(os.Stdout)}
	pio := &pcapIO{r: reader, port: *port, flows: make(map[string]uint32)}
	expressions, err := ruleset.ExprRulesFromYAML(*ruleFile)
	if err != nil {
		return err
	}
	ans := []analyzer.Analyzer{&tcp.FETAnalyzer{}, &tcp.HTTPAnalyzer{}, &tcp.SocksAnalyzer{}, &tcp.SSHAnalyzer{}, &tcp.TLSAnalyzer{}, &tcp.TrojanAnalyzer{}, &udp.DNSAnalyzer{}, &udp.OpenVPNAnalyzer{}, &udp.QUICAnalyzer{}, &udp.WireGuardAnalyzer{}}
	rs, err := ruleset.CompileExprRules(expressions, ans, nil, &ruleset.BuiltinConfig{Logger: l, ProtectedDialContext: pio.ProtectedDialContext})
	if err != nil {
		return err
	}
	en, err := engine.NewEngine(engine.Config{IO: pio, Logger: l, Ruleset: rs, Workers: 1})
	if err != nil {
		return err
	}
	err = en.Run(context.Background())
	if err != nil && !errors.Is(err, stdIO.EOF) {
		return err
	}
	l.emit(map[string]any{"event": "complete", "packets": pio.packets, "skipped_packets": pio.skipped, "bidirectional_tuples": len(pio.flows), "offline": true, "upstream": "HyNetworks/OpenGFW v0.4.3 dcf8348118c6184fe950fcd7da714227ac4ea7a0"})
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
