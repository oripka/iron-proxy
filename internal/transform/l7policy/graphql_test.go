package l7policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectOperation(t *testing.T) {
	cases := []struct {
		name          string
		document      string
		operationName string
		want          operation
		wantErr       bool
	}{
		{name: "shorthand query", document: `{ viewer { login } }`, want: operation{kind: "query"}},
		{name: "anonymous query", document: `query { viewer { login } }`, want: operation{kind: "query"}},
		{name: "named mutation", document: `mutation AddStar($id: ID!) { addStar(input: {starrableId: $id}) { clientMutationId } }`, want: operation{kind: "mutation", name: "AddStar"}},
		{name: "anonymous with variables", document: `subscription($x: Int = 1) { tick(x: $x) }`, want: operation{kind: "subscription"}},
		{name: "object default value in variables", document: `query Q($f: Filter = {a: {b: 1}}) { items(f: $f) { id } }`, want: operation{kind: "query", name: "Q"}},
		{name: "directives before selection", document: `query Q @live { a }`, want: operation{kind: "query", name: "Q"}},
		{
			name:     "comments and strings hide keywords",
			document: "# mutation Evil { drop }\nquery Safe { a(s: \"} mutation X {\", b: \"\"\"\nmutation Y { }\n\\\"\"\" \"\"\") }",
			want:     operation{kind: "query", name: "Safe"},
		},
		{
			name:     "fragments are skipped",
			document: `fragment F on User { login } query Me { viewer { ...F ... on User { id } } }`,
			want:     operation{kind: "query", name: "Me"},
		},
		{
			name:          "operationName selects among several",
			document:      `query A { a } mutation B { b }`,
			operationName: "B",
			want:          operation{kind: "mutation", name: "B"},
		},
		{name: "several operations without operationName", document: `query A { a } mutation B { b }`, wantErr: true},
		{name: "operationName not found", document: `query A { a }`, operationName: "B", wantErr: true},
		{name: "duplicate operation names", document: `query A { a } mutation A { b }`, operationName: "A", wantErr: true},
		{name: "unbalanced braces", document: `query { a { b }`, wantErr: true},
		{name: "mismatched brackets", document: `query { a(x: [1) }`, wantErr: true},
		{name: "unterminated string", document: `query { a(s: "x) }`, wantErr: true},
		{name: "unterminated block string", document: `query { a(s: """x) }`, wantErr: true},
		{name: "type system definition", document: `type Query { a: Int }`, wantErr: true},
		{name: "keywords are case sensitive", document: `Mutation { a }`, wantErr: true},
		{name: "fragment only", document: `fragment F on User { id }`, wantErr: true},
		{name: "empty", document: "  # nothing\n", wantErr: true},
		{name: "missing selection set", document: `query Q($a: Int)`, wantErr: true},
		{name: "unexpected character", document: `query { a % b }`, wantErr: true},
		{name: "leading BOM", document: "\ufeffquery Q { a }", want: operation{kind: "query", name: "Q"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectOperation(tc.document, tc.operationName)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
