package l7policy

import (
	"errors"
	"fmt"
	"strings"
)

// operation is a top-level GraphQL operation definition.
type operation struct {
	kind string // query, mutation, or subscription
	name string // empty for anonymous operations
}

type tokenKind int

const (
	tokPunct tokenKind = iota
	tokName
	tokString
	tokNumber
)

type token struct {
	kind  tokenKind
	value string
}

// selectOperation returns the operation a GraphQL server would execute for
// document and operationName: the operation with that name, or the only
// operation when operationName is empty.
func selectOperation(document, operationName string) (operation, error) {
	ops, err := parseOperations(document)
	if err != nil {
		return operation{}, err
	}
	if operationName == "" {
		if len(ops) != 1 {
			return operation{}, fmt.Errorf("document has %d operations and no operationName", len(ops))
		}
		return ops[0], nil
	}
	var found *operation
	for i := range ops {
		if ops[i].name == operationName {
			if found != nil {
				return operation{}, fmt.Errorf("duplicate operation %q", operationName)
			}
			found = &ops[i]
		}
	}
	if found == nil {
		return operation{}, fmt.Errorf("operation %q not found", operationName)
	}
	return *found, nil
}

// parseOperations lists the operation definitions in an executable GraphQL
// document. It is deliberately shallow: selection sets, arguments, and
// fragment bodies are skipped by bracket matching, and anything other than
// operations and fragments at the top level is an error.
func parseOperations(document string) ([]operation, error) {
	toks, err := lex(document)
	if err != nil {
		return nil, err
	}
	var ops []operation
	for i := 0; i < len(toks); {
		t := toks[i]
		switch {
		case t.kind == tokPunct && t.value == "{":
			ops = append(ops, operation{kind: "query"})
			if i, err = skipBlock(toks, i); err != nil {
				return nil, err
			}
		case t.kind == tokName && (t.value == "query" || t.value == "mutation" || t.value == "subscription"):
			op := operation{kind: t.value}
			i++
			if i < len(toks) && toks[i].kind == tokName {
				op.name = toks[i].value
				i++
			}
			if i, err = skipHeader(toks, i); err != nil {
				return nil, err
			}
			if i, err = skipBlock(toks, i); err != nil {
				return nil, err
			}
			ops = append(ops, op)
		case t.kind == tokName && t.value == "fragment":
			if i, err = skipHeader(toks, i+1); err != nil {
				return nil, err
			}
			if i, err = skipBlock(toks, i); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected top-level token %q", t.value)
		}
	}
	if len(ops) == 0 {
		return nil, errors.New("no operations")
	}
	return ops, nil
}

// skipHeader advances past variable definitions and directives to the
// opening brace of the selection set. Braces inside parentheses or brackets
// (object default values) do not end the header.
func skipHeader(toks []token, i int) (int, error) {
	depth := 0
	for ; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tokPunct {
			continue
		}
		switch t.value {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
			if depth < 0 {
				return 0, errors.New("unbalanced brackets")
			}
		case "{":
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errors.New("missing selection set")
}

// skipBlock expects toks[i] to be "{" and returns the index after its
// matching "}".
func skipBlock(toks []token, i int) (int, error) {
	if i >= len(toks) || toks[i].kind != tokPunct || toks[i].value != "{" {
		return 0, errors.New("expected {")
	}
	var stack []string
	for ; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tokPunct {
			continue
		}
		switch t.value {
		case "{", "(", "[":
			stack = append(stack, t.value)
		case "}", ")", "]":
			open := map[string]string{"}": "{", ")": "(", "]": "["}[t.value]
			if len(stack) == 0 || stack[len(stack)-1] != open {
				return 0, errors.New("unbalanced brackets")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, errors.New("unterminated selection set")
}

// lex tokenizes a GraphQL document, dropping whitespace, commas, and
// comments. String and number values are kept only as opaque tokens.
func lex(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case strings.HasPrefix(src[i:], "\xef\xbb\xbf"):
			i += len("\xef\xbb\xbf")
		case c == '#':
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
		case strings.HasPrefix(src[i:], "..."):
			toks = append(toks, token{kind: tokPunct, value: "..."})
			i += 3
		case strings.IndexByte("!$&()[]{}:=@|", c) >= 0:
			toks = append(toks, token{kind: tokPunct, value: string(c)})
			i++
		case c == '_' || isLetter(c):
			start := i
			for i < len(src) && (src[i] == '_' || isLetter(src[i]) || isDigit(src[i])) {
				i++
			}
			toks = append(toks, token{kind: tokName, value: src[start:i]})
		case c == '-' || isDigit(c):
			start := i
			i++
			for i < len(src) && (isDigit(src[i]) || strings.IndexByte(".eE+-", src[i]) >= 0) {
				i++
			}
			toks = append(toks, token{kind: tokNumber, value: src[start:i]})
		case strings.HasPrefix(src[i:], `"""`):
			end, err := blockStringEnd(src, i+3)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokString})
			i = end
		case c == '"':
			end, err := stringEnd(src, i+1)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokString})
			i = end
		default:
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	return toks, nil
}

// stringEnd returns the index after the closing quote of a regular string
// whose contents start at i.
func stringEnd(src string, i int) (int, error) {
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, nil
		case '\n', '\r':
			return 0, errors.New("unterminated string")
		default:
			i++
		}
	}
	return 0, errors.New("unterminated string")
}

// blockStringEnd returns the index after the closing """ of a block string
// whose contents start at i. Only \""" is an escape inside block strings.
func blockStringEnd(src string, i int) (int, error) {
	for i < len(src) {
		if strings.HasPrefix(src[i:], `\"""`) {
			i += 4
			continue
		}
		if strings.HasPrefix(src[i:], `"""`) {
			return i + 3, nil
		}
		i++
	}
	return 0, errors.New("unterminated block string")
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
