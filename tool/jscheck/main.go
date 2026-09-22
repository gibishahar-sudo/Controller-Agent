// Command jscheck is a release gate for the controller web UI: it parses
// the served index.html script block (strings/comments/templates/regex
// aware) and fails on the first unbalanced delimiter with an HTML line
// number. Two shipped releases died to a missing brace killing the whole
// UI script with zero visible error; run this before every release:
// go run ./tool/jscheck (must print BALANCED OK).
//
// Phase 2 is a DOM-order gate: v1.4.29/1.4.30 shipped a page whose script
// died at parse with "Cannot set properties of null (setting 'onclick')"
// because #wizOverlay was moved after </script> while a top-level binding
// referenced it. Every id referenced via $("...") in a top-level statement
// must therefore be defined by id="..." BEFORE the <script> tag.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

type frame struct {
	ch   byte // '{', '(', '[', 'T' (template ${...} marker uses '{' too)
	line int
}

type ref struct {
	id   string
	line int
}

var topRefs []ref

func main() {
	b, err := os.ReadFile("internal/ui/frontend/index.html")
	if err != nil {
		fmt.Println("READ FAIL:", err)
		os.Exit(1)
	}
	s := string(b)
	si := strings.Index(s, "<script>")
	ei := strings.Index(s, "</script>")
	js := s[si+8 : ei]
	baseLine := strings.Count(s[:si], "\n") // 0-based offset of script start

	var stack []frame
	mode := 0 // 0=code, 1=template
	tmplDepth := 0
	line := 1
	lastOperand := true // start-of-statement: a '/' begins regex/comment
	i := 0
	n := len(js)
	isIdent := func(c byte) bool {
		return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	for i < n {
		c := js[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if mode == 1 {
			// inside template literal text
			if c == '\\' {
				i += 2
				continue
			}
			if c == '`' {
				mode = 0
				lastOperand = true
				i++
				continue
			}
			if c == '$' && i+1 < n && js[i+1] == '{' {
				stack = append(stack, frame{'T', baseLine + line})
				mode = 0
				lastOperand = true
				i += 2
				continue
			}
			i++
			continue
		}
		// code mode
		if c == ' ' || c == '\t' || c == '\r' || c == ';' || c == ',' || c == ':' || c == '?' {
			i++
			continue
		}
		if isIdent(c) {
			start := i
			for i < n && isIdent(js[i]) {
				i++
			}
			word := js[start:i]
			if word == "$" && len(stack) == 0 {
				// top-level $("literal") reference? record (id, line) for
				// the DOM-order gate below. Non-literals (dynamic) skip.
				j := i
				for j < n && (js[j] == ' ' || js[j] == '\t') {
					j++
				}
				if j < n && js[j] == '(' {
					j++
					for j < n && (js[j] == ' ' || js[j] == '\t') {
						j++
					}
					if j < n && (js[j] == '"' || js[j] == '\'') {
						q := js[j]
						j++
						k := j
						for k < n && js[k] != q {
							if js[k] == '\\' {
								k++
							}
							k++
						}
						lit := js[j:k]
						k++
						for k < n && (js[k] == ' ' || js[k] == '\t') {
							k++
						}
						if k < n && js[k] == ')' {
							topRefs = append(topRefs, ref{id: lit, line: baseLine + line})
						}
					}
				}
			}
			lastOperand = true
			continue
		}
		if c == '"' || c == '\'' {
			q := c
			i++
			for i < n {
				if js[i] == '\\' {
					i += 2
					continue
				}
				if js[i] == '\n' {
					line++
				}
				if js[i] == q {
					i++
					break
				}
				i++
			}
			lastOperand = true
			continue
		}
		if c == '`' {
			mode = 1
			tmplDepth++
			i++
			continue
		}
		if c == '/' {
			if i+1 < n && js[i+1] == '/' {
				for i < n && js[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < n && js[i+1] == '*' {
				i += 2
				for i+1 < n && !(js[i] == '*' && js[i+1] == '/') {
					if js[i] == '\n' {
						line++
					}
					i++
				}
				i += 2
				continue
			}
			if lastOperand {
				i++ // division
				lastOperand = false
				continue
			}
			// regex literal: consume to unescaped /
			i++
			for i < n {
				if js[i] == '\\' {
					i += 2
					continue
				}
				if js[i] == '\n' {
					line++
				}
				if js[i] == '/' {
					break
				}
				if js[i] == '[' {
					// char class may contain /; skip to ]
					i++
					for i < n && js[i] != ']' {
						if js[i] == '\\' {
							i++
						}
						if js[i] == '\n' {
							line++
						}
						i++
					}
					continue
				}
				i++
			}
			i++ // past /
			for i < n && ((js[i] >= 'a' && js[i] <= 'z') || (js[i] >= 'A' && js[i] <= 'Z')) {
				i++ // flags
			}
			lastOperand = true
			continue
		}
		switch c {
		case '{', '(', '[':
			stack = append(stack, frame{c, baseLine + line})
			lastOperand = false
			if c == '(' {
				// keep operand false (call/group start)
			}
		case '}':
			if len(stack) == 0 {
				fmt.Printf("EXTRA } at html line %d\n", baseLine+line)
				return
			}
			top := stack[len(stack)-1]
			if top.ch == 'T' || top.ch == '{' {
				stack = stack[:len(stack)-1]
				if top.ch == 'T' {
					mode = 1
				}
				lastOperand = true
			} else {
				fmt.Printf("MISMATCH } at html line %d, top was %c opened at html line %d\n", baseLine+line, top.ch, top.line)
				return
			}
		case ')', ']':
			want := byte('(')
			if c == ']' {
				want = '['
			}
			if len(stack) == 0 {
				fmt.Printf("EXTRA %c at html line %d\n", c, baseLine+line)
				return
			}
			top := stack[len(stack)-1]
			if top.ch != want {
				fmt.Printf("MISMATCH %c at html line %d, top was %c opened at html line %d\n", c, baseLine+line, top.ch, top.line)
				return
			}
			stack = stack[:len(stack)-1]
			lastOperand = true
		default:
			// operators
			if c == '+' || c == '-' {
				// could be ++/-- (operand-ish); harmless either way for balance
				if i+1 < n && js[i+1] == c {
					lastOperand = true
					i += 2
					continue
				}
			}
			lastOperand = false
		}
		i++
	}
	if mode == 1 {
		fmt.Println("UNTERMINATED template literal at EOF")
		return
	}
	if len(stack) > 0 {
		fmt.Printf("UNCLOSED %d opener(s); innermost %c opened at html line %d\n", len(stack), stack[len(stack)-1].ch, stack[len(stack)-1].line)
		return
	}
	fmt.Println("BALANCED OK")
	// DOM-order gate: top-level $("id") must resolve at parse time, i.e.
	// the id must be defined before <script>.
	head := s[:si]
	idDef := regexp.MustCompile(`id="([^"]+)"`)
	defined := map[string]bool{}
	for _, m := range idDef.FindAllStringSubmatch(head, -1) {
		defined[m[1]] = true
	}
	bad := 0
	seen := map[string]int{} // id -> first ref line (report once)
	for _, r := range topRefs {
		if defined[r.id] {
			continue
		}
		if _, dup := seen[r.id]; dup {
			continue
		}
		seen[r.id] = r.line
		fmt.Printf("LATE-ID %q referenced at top level (html line %d) but no id=%q before <script> — page script would die with null\n", r.id, r.line, r.id)
		bad++
	}
	if bad > 0 {
		os.Exit(1)
	}
	fmt.Printf("DOM-ORDER OK (%d top-level refs)\n", len(topRefs))
}
