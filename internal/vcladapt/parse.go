package vcladapt

// vclFile is the parsed (best-effort) model of a VCL source.
type vclFile struct {
	backends []*backend
	subs     map[string][]stmt
	subOrder []string
	acls     []string // acl names (→ TODO)
	imports  []string // vmod imports (→ TODO)
	includes []string // include files (→ TODO)
	others   []string // other unrecognized top-level constructs (→ TODO)
}

// backend is a parsed `backend NAME { .host=…; .port=…; .probe=… }`.
type backend struct {
	name  string
	host  string
	port  string
	probe *probe
}

// probe holds the health-check fields we can map to a cadish `health` line.
type probe struct {
	url       string
	method    string
	expect    string
	interval  string
	window    string
	threshold string
}

// clause is one (condition, body) arm of an if/else-if chain.
type clause struct {
	cond []token
	body []stmt
}

// stmt is either an if-chain or a simple statement (the tokens before its ';').
type stmt struct {
	isIf    bool
	clauses []clause
	els     []stmt
	simple  []token
	line    int
}

// maxParseDepth bounds how deeply if/else blocks may nest. parseBlock recurses
// (parseBlock -> parseIf -> parseBraceBlock -> parseBlock), so an adversarial VCL of
// the form `if(x){if(x){…}}` nested millions deep would otherwise grow the goroutine
// stack until the runtime aborts with a fatal "goroutine stack exceeds" error that
// recover() cannot catch. Adapt is best-effort and never errors, so on hitting the cap
// the parser stops MODELLING the over-deep body and drains it iteratively (skipBlock)
// instead of recursing — the skeleton loses nothing a human would want from a block
// nested 1000+ levels, and the attack becomes a clean, bounded parse. Mirrors
// cadishfile's maxBlockDepth. Real VCL nests only a handful of levels.
const maxParseDepth = 1000

type parser struct {
	toks  []token
	pos   int
	depth int
}

func parse(src string) *vclFile {
	p := &parser{toks: lex(src)}
	f := &vclFile{subs: map[string][]stmt{}}
	p.parseTop(f)
	return f
}

func (p *parser) cur() token { return p.toks[p.pos] }
func (p *parser) eat() token {
	t := p.toks[p.pos]
	if t.kind != tEOF {
		p.pos++
	}
	return t
}
func (p *parser) isP(s string) bool {
	return p.cur().kind == tPunct && p.cur().text == s
}

func (p *parser) parseTop(f *vclFile) {
	for p.cur().kind != tEOF {
		t := p.cur()
		if t.kind == tPunct {
			p.eat() // stray ; or }
			continue
		}
		if t.kind != tIdent {
			p.eat()
			continue
		}
		switch t.text {
		case "vcl":
			p.skipToSemi()
		case "import":
			p.eat()
			if p.cur().kind == tIdent {
				f.imports = append(f.imports, p.cur().text)
			}
			p.skipToSemi()
		case "include":
			p.eat()
			if p.cur().kind == tStr {
				f.includes = append(f.includes, p.cur().text)
			}
			p.skipToSemi()
		case "backend":
			p.eat()
			name := p.eatIdent()
			f.backends = append(f.backends, p.parseBackend(name))
		case "probe":
			p.eat()
			_ = p.eatIdent()
			p.skipBlock() // standalone probe defs: referenced by name; not mapped
		case "acl":
			p.eat()
			f.acls = append(f.acls, p.eatIdent())
			p.skipBlock()
		case "sub":
			p.eat()
			name := p.eatIdent()
			if _, seen := f.subs[name]; !seen {
				f.subOrder = append(f.subOrder, name)
			}
			if p.isP("{") {
				p.eat()
				f.subs[name] = p.parseBlock()
			}
		default:
			// Unknown top-level construct: record it and skip its block/statement.
			f.others = append(f.others, t.text)
			p.eat()
			if p.isP("{") {
				p.skipBlock()
			} else {
				p.skipToSemi()
			}
		}
	}
}

// parseBackend reads a backend body for .host/.port/.probe.
func (p *parser) parseBackend(name string) *backend {
	b := &backend{name: name}
	if !p.isP("{") {
		return b
	}
	p.eat() // {
	for !p.isP("}") && p.cur().kind != tEOF {
		t := p.cur()
		if t.kind == tIdent && t.text == ".host" {
			p.eat()
			b.host = p.assignValue()
			continue
		}
		if t.kind == tIdent && t.text == ".port" {
			p.eat()
			b.port = p.assignValue()
			continue
		}
		if t.kind == tIdent && t.text == ".probe" {
			p.eat()
			if p.isP("=") {
				p.eat()
			}
			if p.isP("{") {
				b.probe = p.parseProbe()
			} else {
				p.skipToSemi() // .probe = name;
			}
			continue
		}
		p.eat()
	}
	if p.isP("}") {
		p.eat()
	}
	return b
}

// parseProbe reads a `.probe = { .url=…; .expected_response=…; … }` block.
func (p *parser) parseProbe() *probe {
	pr := &probe{}
	p.eat() // {
	for !p.isP("}") && p.cur().kind != tEOF {
		t := p.cur()
		if t.kind == tIdent {
			switch t.text {
			case ".url", ".request":
				p.eat()
				pr.url = p.assignValue()
				continue
			case ".expected_response":
				p.eat()
				pr.expect = p.assignValue()
				continue
			case ".interval":
				p.eat()
				pr.interval = p.assignValue()
				continue
			case ".window":
				p.eat()
				pr.window = p.assignValue()
				continue
			case ".threshold":
				p.eat()
				pr.threshold = p.assignValue()
				continue
			}
		}
		p.eat()
	}
	if p.isP("}") {
		p.eat()
	}
	return pr
}

// assignValue consumes `= VALUE ;` and returns VALUE's text (string or number).
func (p *parser) assignValue() string {
	if p.isP("=") {
		p.eat()
	}
	val := ""
	if p.cur().kind == tStr || p.cur().kind == tNum || p.cur().kind == tIdent {
		val = p.cur().text
		p.eat()
	}
	p.skipToSemi()
	return val
}

// parseBlock parses statements until the matching '}' (which it consumes).
func (p *parser) parseBlock() []stmt {
	// Depth cap (Fix 3): beyond maxParseDepth, stop recursing and drain the rest of this
	// block iteratively so a pathologically nested `if(){…}` cannot overflow the stack.
	p.depth++
	if p.depth > maxParseDepth {
		p.depth--
		p.drainBlock()
		return nil
	}
	defer func() { p.depth-- }()

	var out []stmt
	for {
		t := p.cur()
		if t.kind == tEOF {
			return out
		}
		if p.isP("}") {
			p.eat()
			return out
		}
		if p.isP(";") {
			p.eat()
			continue
		}
		if t.kind == tIdent && t.text == "if" {
			out = append(out, p.parseIf())
			continue
		}
		out = append(out, p.parseSimple())
	}
}

// parseIf parses an if/else-if/else chain.
func (p *parser) parseIf() stmt {
	s := stmt{isIf: true, line: p.cur().line}
	p.eat() // if
	cond := p.parseParens()
	body := p.parseBraceBlock()
	s.clauses = append(s.clauses, clause{cond: cond, body: body})
	for p.cur().kind == tIdent && p.cur().text == "else" {
		p.eat() // else
		if p.cur().kind == tIdent && p.cur().text == "if" {
			p.eat()
			c := p.parseParens()
			b := p.parseBraceBlock()
			s.clauses = append(s.clauses, clause{cond: c, body: b})
			continue
		}
		s.els = p.parseBraceBlock()
		break
	}
	return s
}

// parseSimple collects tokens up to ';' (or a '{' block, which it captures-then-skips).
func (p *parser) parseSimple() stmt {
	s := stmt{line: p.cur().line}
	for {
		t := p.cur()
		if t.kind == tEOF || p.isP("}") {
			return s
		}
		if p.isP(";") {
			p.eat()
			return s
		}
		if p.isP("{") {
			p.skipBlock() // a block-bearing statement we don't model
			return s
		}
		s.simple = append(s.simple, t)
		p.eat()
	}
}

// parseParens returns the tokens inside a balanced (...) group.
func (p *parser) parseParens() []token {
	var out []token
	if !p.isP("(") {
		return out
	}
	p.eat()
	depth := 1
	for p.cur().kind != tEOF {
		if p.isP("(") {
			depth++
		} else if p.isP(")") {
			depth--
			if depth == 0 {
				p.eat()
				return out
			}
		}
		out = append(out, p.cur())
		p.eat()
	}
	return out
}

// parseBraceBlock parses a `{ … }` block into statements.
func (p *parser) parseBraceBlock() []stmt {
	if !p.isP("{") {
		return nil
	}
	p.eat()
	return p.parseBlock()
}

// drainBlock iteratively consumes tokens up to and including the '}' that closes the
// CURRENTLY-OPEN block (its opening '{' was already eaten by the caller). It is the
// non-recursive fallback parseBlock uses past the depth cap so deeply nested input is
// discarded without growing the stack. Brace depth starts at 1 (inside the open block).
func (p *parser) drainBlock() {
	depth := 1
	for p.cur().kind != tEOF && depth > 0 {
		if p.isP("{") {
			depth++
		} else if p.isP("}") {
			depth--
		}
		p.eat()
	}
}

func (p *parser) skipToSemi() {
	for p.cur().kind != tEOF && !p.isP(";") {
		p.eat()
	}
	if p.isP(";") {
		p.eat()
	}
}

func (p *parser) skipBlock() {
	for p.cur().kind != tEOF && !p.isP("{") {
		if p.isP(";") {
			p.eat()
			return
		}
		p.eat()
	}
	if !p.isP("{") {
		return
	}
	p.eat()
	depth := 1
	for p.cur().kind != tEOF && depth > 0 {
		if p.isP("{") {
			depth++
		} else if p.isP("}") {
			depth--
		}
		p.eat()
	}
}

func (p *parser) eatIdent() string {
	if p.cur().kind == tIdent {
		return p.eat().text
	}
	return ""
}
