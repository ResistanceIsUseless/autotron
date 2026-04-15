// Package graph provides Neo4j graph database types, connection management,
// and data persistence for the ASM pipeline. All enricher results flow through
// this package — enrichers never write to Neo4j directly.
package graph

import "time"

// NodeType identifies the label applied to a Neo4j node.
type NodeType string

const (
	NodeDomain      NodeType = "Domain"
	NodeSubdomain   NodeType = "Subdomain"
	NodeIP          NodeType = "IP"
	NodeService     NodeType = "Service"
	NodeCertificate NodeType = "Certificate"
	NodeURL         NodeType = "URL"
	NodeTechnology  NodeType = "Technology"
	NodeJSFile      NodeType = "JSFile"
	NodeEndpoint    NodeType = "Endpoint"
	NodeForm        NodeType = "Form"
	NodeFinding     NodeType = "Finding"
	NodeScanRun     NodeType = "ScanRun"
)

// RelType identifies a relationship type in the graph.
type RelType string

const (
	RelHAS           RelType = "HAS"
	RelCNAME         RelType = "CNAME"
	RelRESOLVES_TO   RelType = "RESOLVES_TO"
	RelHAS_SERVICE   RelType = "HAS_SERVICE"
	RelPRESENTS      RelType = "PRESENTS"
	RelSERVES        RelType = "SERVES"
	RelRUNS          RelType = "RUNS"
	RelLOADS         RelType = "LOADS"
	RelEXPOSES       RelType = "EXPOSES"
	RelCONTAINS      RelType = "CONTAINS"
	RelHAS_FINDING   RelType = "HAS_FINDING"
	RelDISCOVERED_BY RelType = "DISCOVERED_BY"
)

// BaseProps are attached to every node in the graph. They provide provenance,
// scope status, and the enriched_by cycle brake.
type BaseProps struct {
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	DiscoveryDepth int       `json:"discovery_depth"` // 0 for seeds, parent+1
	ScanRunID      string    `json:"scan_run_id"`
	EnrichedBy     []string  `json:"enriched_by"` // cycle brake: ["subscope","dnsx",...]
	InScope        bool      `json:"in_scope"`
}

// Node is a graph node with a type, primary key, and arbitrary properties.
// Properties are stored as map[string]any for flexibility — each parser
// populates the fields relevant to its node type.
type Node struct {
	Type       NodeType       `json:"type"`
	PrimaryKey string         `json:"primary_key"` // value of the uniqueness field
	Props      map[string]any `json:"props"`       // all properties including BaseProps fields
}

// PendingWork is a dispatch unit returned by graph queries. It always includes
// a triggering node and may include edge-derived context used for template
// expansion (for example DNS-first HTTP resolution data).
type PendingWork struct {
	Node      Node
	EdgeProps map[string]any
}

// Edge represents a relationship between two nodes.
type Edge struct {
	Type     RelType        `json:"type"`
	FromType NodeType       `json:"from_type"`
	FromKey  string         `json:"from_key"`
	ToType   NodeType       `json:"to_type"`
	ToKey    string         `json:"to_key"`
	Props    map[string]any `json:"props,omitempty"`
}

// Finding is a vulnerability, observation, or security-relevant result.
// Polymorphic — the Type field distinguishes variants (e.g. "ssh-weak-kex",
// "open-redirect", "exposed-dotgit"). Rooted on whichever node it belongs to.
type Finding struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`   // info|low|medium|high|critical
	Confidence string         `json:"confidence"` // tentative|firm|confirmed
	Tool       string         `json:"tool"`
	CVE        []string       `json:"cve,omitempty"`
	CWE        []string       `json:"cwe,omitempty"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// FindingSummary is a read model used by reporting views.
type FindingSummary struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Type         string   `json:"type"`
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	Tools        []string `json:"tools"`
	AssetCount   int64    `json:"asset_count"`
	Assets       []string `json:"assets"`
	LastSeen     string   `json:"last_seen"`
	CanonicalKey string   `json:"canonical_key"`
}

type TopFindingsOptions struct {
	Limit      int
	Severity   string
	Confidence string
	Tool       string
	Since      string
}

// PrimaryKeyField returns the Neo4j property name used as the uniqueness
// constraint for a given node type. This is the single source of truth for
// the MERGE key in upsert operations.
func PrimaryKeyField(nt NodeType) string {
	switch nt {
	case NodeDomain:
		return "fqdn"
	case NodeSubdomain:
		return "fqdn"
	case NodeIP:
		return "address"
	case NodeService:
		return "ip_port"
	case NodeCertificate:
		return "sha256"
	case NodeURL:
		return "url"
	case NodeTechnology:
		return "tech_id"
	case NodeJSFile:
		return "jsfile_id"
	case NodeEndpoint:
		return "endpoint_id"
	case NodeForm:
		return "form_id"
	case NodeFinding:
		return "id"
	case NodeScanRun:
		return "id"
	default:
		return "id"
	}
}

// Constraints returns the Cypher statements needed to initialize the Neo4j
// schema. These are idempotent (IF NOT EXISTS).
func Constraints() []string {
	return []string{
		`CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (n:Domain) REQUIRE n.fqdn IS UNIQUE`,
		`CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (n:Subdomain) REQUIRE n.fqdn IS UNIQUE`,
		`CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE`,
		`CREATE CONSTRAINT service_key IF NOT EXISTS FOR (n:Service) REQUIRE n.ip_port IS UNIQUE`,
		`CREATE CONSTRAINT cert_sha IF NOT EXISTS FOR (n:Certificate) REQUIRE n.sha256 IS UNIQUE`,
		`CREATE CONSTRAINT url_unique IF NOT EXISTS FOR (n:URL) REQUIRE n.url IS UNIQUE`,
		`CREATE CONSTRAINT tech_id_key IF NOT EXISTS FOR (n:Technology) REQUIRE n.tech_id IS UNIQUE`,
		`CREATE CONSTRAINT jsfile_id_key IF NOT EXISTS FOR (n:JSFile) REQUIRE n.jsfile_id IS UNIQUE`,
		`CREATE CONSTRAINT endpoint_id_key IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.endpoint_id IS UNIQUE`,
		`CREATE CONSTRAINT form_id_key IF NOT EXISTS FOR (n:Form) REQUIRE n.form_id IS UNIQUE`,

		// Backward-compat constraints retained while data migrates to synthetic IDs.
		`CREATE CONSTRAINT tech_key IF NOT EXISTS FOR (n:Technology) REQUIRE (n.name, n.version) IS UNIQUE`,
		`CREATE CONSTRAINT js_key IF NOT EXISTS FOR (n:JSFile) REQUIRE (n.url, n.sha256) IS UNIQUE`,
		`CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE`,
		`CREATE CONSTRAINT scanrun_id IF NOT EXISTS FOR (n:ScanRun) REQUIRE n.id IS UNIQUE`,
	}
}

// Indexes returns the Cypher statements for secondary indexes. Separate from
// constraints so callers can apply them independently.
func Indexes() []string {
	return []string{
		`CREATE INDEX subdomain_status IF NOT EXISTS FOR (n:Subdomain) ON (n.status)`,
		`CREATE INDEX service_product IF NOT EXISTS FOR (n:Service) ON (n.product)`,
		`CREATE INDEX url_status IF NOT EXISTS FOR (n:URL) ON (n.status_code)`,
		`CREATE INDEX finding_severity IF NOT EXISTS FOR (n:Finding) ON (n.severity)`,
		`CREATE INDEX finding_tool IF NOT EXISTS FOR (n:Finding) ON (n.tool)`,
		`CREATE INDEX finding_canonical IF NOT EXISTS FOR (n:Finding) ON (n.canonical_key)`,
		`CREATE INDEX node_inscope IF NOT EXISTS FOR (n:Subdomain) ON (n.in_scope)`,
	}
}
