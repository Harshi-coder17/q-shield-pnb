# backend/analysis/dep_graph.py
# Q-Shield — Cryptographic Dependency Graph Engine
# Owner: Member 3 (PQC Intelligence & Frontend Dashboard Engineer)
# SRS References: Feature 3, FR-17 (Certificate Reuse Detection)

import networkx as nx
import json
from collections import defaultdict

# ── Node Styling ───────────────────────────────────────────────────────────────

NODE_COLORS = {
    'asset':       '#2471A3',   # Blue      — scanned host
    'certificate': '#27AE60',   # Green     — X.509 certificate
    'ca':          '#D4AC0D',   # Gold      — Certificate Authority
    'algorithm':   '#E74C3C',   # Red       — crypto algorithm
    'protocol':    '#8E44AD',   # Purple    — TLS protocol version
}

NODE_SHAPES = {
    'asset':       'ellipse',
    'certificate': 'box',
    'ca':          'diamond',
    'algorithm':   'triangle',
    'protocol':    'dot',
}

# Score → node border color (visual risk indicator on asset nodes)
def _score_to_color(score):
    if score is None:
        return '#95A5A6'
    if score >= 90:
        return '#27AE60'   # Green  — Fully Quantum Safe
    if score >= 60:
        return '#F39C12'   # Orange — PQC Ready
    if score >= 30:
        return '#E74C3C'   # Red    — Quantum Vulnerable
    return '#1C2833'       # Dark   — Critical


# ── Main Engine ────────────────────────────────────────────────────────────────

class DependencyGraphEngine:
    """
    Builds a directed cryptographic dependency graph across all scanned assets.

    Graph structure per asset:
        [asset] ──uses_certificate──► [certificate]
        [certificate] ──signed_with──► [algorithm]
        [certificate] ──issued_by────► [CA]
        [asset] ──communicates_via──► [TLS protocol]

    Key capabilities:
    - FR-17: Certificate reuse detection (shared cert across multiple assets)
    - Feature 3: Visual graph export for Vis.js (frontend)
    - Summary stats: algorithm distribution, vulnerable node counts, CA inventory
    """

    def __init__(self):
        self.G = nx.DiGraph()
        self._cert_to_assets = defaultdict(list)   # fingerprint → [hostnames]
        self._algo_to_assets = defaultdict(list)   # algorithm   → [hostnames]
        self._ca_to_certs    = defaultdict(list)   # CA name     → [cert fps]

    # ── Graph Construction ─────────────────────────────────────────────────────

    def add_scan_result(self, scan_data: dict):
        """
        Ingest one scan result and add its nodes + edges to the graph.

        Expected keys in scan_data:
            hostname              (str)  — e.g. 'pnb.co.in'
            cert_sha1_fingerprint (str)  — hex fingerprint (or cert_sha1_fp)
            cert_issuer           (str)  — CA distinguished name
            cert_sig_algorithm    (str)  — e.g. 'RSA-SHA256', 'ML-DSA-65'
            tls_version           (str)  — e.g. 'TLSv1.3'
            quantum_score         (float)— 0–100
            label                 (str)  — 'Fully Quantum Safe' / 'Critical' etc.
            hndl_risk             (str)  — 'HIGH' / 'MEDIUM' / 'LOW'
        """
        host      = scan_data.get('hostname', 'unknown')
        cert_fp   = (
            scan_data.get('cert_sha1_fingerprint') or
            scan_data.get('cert_sha1_fp') or
            'unknown_cert'
        )
        cert_fp   = cert_fp[:20] if cert_fp else 'unknown_cert'
        issuer    = scan_data.get('cert_issuer', 'Unknown CA')
        alg       = scan_data.get('cert_sig_algorithm', 'Unknown Alg')
        proto     = scan_data.get('tls_version', 'Unknown TLS')
        score     = scan_data.get('quantum_score', 0)
        label     = scan_data.get('label', 'Unknown')
        hndl_risk = scan_data.get('hndl_risk', 'UNKNOWN')

        asset_color = _score_to_color(score)

        # ── Add Nodes ──────────────────────────────────────────────────────────
        self.G.add_node(
            host,
            node_type  = 'asset',
            label      = host,
            color      = asset_color,
            score      = score,
            pqc_label  = label,
            hndl_risk  = hndl_risk,
        )
        self.G.add_node(
            cert_fp,
            node_type = 'certificate',
            label     = f'Cert:{cert_fp[:8]}',
            color     = NODE_COLORS['certificate'],
            full_fp   = cert_fp,
        )
        self.G.add_node(
            issuer,
            node_type = 'ca',
            label     = issuer[:30],
            color     = NODE_COLORS['ca'],
        )
        self.G.add_node(
            alg,
            node_type = 'algorithm',
            label     = alg[:25],
            color     = NODE_COLORS['algorithm'],
        )
        self.G.add_node(
            proto,
            node_type = 'protocol',
            label     = proto,
            color     = NODE_COLORS['protocol'],
        )

        # ── Add Edges ──────────────────────────────────────────────────────────
        self.G.add_edge(host,     cert_fp, rel='uses_certificate')
        self.G.add_edge(cert_fp,  alg,     rel='signed_with')
        self.G.add_edge(cert_fp,  issuer,  rel='issued_by')
        self.G.add_edge(host,     proto,   rel='communicates_via')

        # ── Bookkeeping ────────────────────────────────────────────────────────
        if host not in self._cert_to_assets[cert_fp]:
            self._cert_to_assets[cert_fp].append(host)

        if host not in self._algo_to_assets[alg]:
            self._algo_to_assets[alg].append(host)

        if cert_fp not in self._ca_to_certs[issuer]:
            self._ca_to_certs[issuer].append(cert_fp)

    def add_multiple(self, scan_results: list):
        """Convenience method — add a list of scan result dicts at once."""
        for result in scan_results:
            self.add_scan_result(result)

    # ── FR-17: Certificate Reuse Detection ────────────────────────────────────

    def detect_cert_reuse(self) -> list:
        """
        FR-17: Identify certificates shared across multiple assets.

        A reused certificate means a single private key is trusted by
        multiple systems — a single compromise exposes all of them.

        Returns:
            List of dicts: [{ cert_fingerprint, assets, reuse_count }]
            Sorted by reuse_count descending.
        """
        reused = [
            {
                'cert_fingerprint': cert,
                'assets':           assets,
                'reuse_count':      len(assets),
                'risk_note': (
                    'HIGH: Single private key compromise affects '
                    f'{len(assets)} assets simultaneously.'
                ),
            }
            for cert, assets in self._cert_to_assets.items()
            if len(assets) > 1
        ]
        return sorted(reused, key=lambda x: x['reuse_count'], reverse=True)

    # ── Summary & Analytics ───────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """
        Return graph-level statistics for the dashboard summary panel.
        """
        asset_nodes = [
            (n, d) for n, d in self.G.nodes(data=True)
            if d.get('node_type') == 'asset'
        ]
        algo_nodes = [
            n for n, d in self.G.nodes(data=True)
            if d.get('node_type') == 'algorithm'
        ]
        ca_nodes = [
            n for n, d in self.G.nodes(data=True)
            if d.get('node_type') == 'ca'
        ]

        # Algorithm usage frequency
        algo_distribution = {
            alg: len(assets)
            for alg, assets in self._algo_to_assets.items()
        }

        # Count assets by HNDL risk
        hndl_counts = defaultdict(int)
        for _, d in asset_nodes:
            hndl_counts[d.get('hndl_risk', 'UNKNOWN')] += 1

        return {
            'total_nodes':        self.G.number_of_nodes(),
            'total_edges':        self.G.number_of_edges(),
            'total_assets':       len(asset_nodes),
            'unique_algorithms':  len(algo_nodes),
            'unique_cas':         len(ca_nodes),
            'cert_reuse_count':   len(self.detect_cert_reuse()),
            'algorithm_distribution': algo_distribution,
            'hndl_risk_distribution': dict(hndl_counts),
        }

    def get_vulnerable_subgraph(self) -> dict:
        """
        Return a subgraph containing only vulnerable assets and their dependencies.
        Useful for the 'Vulnerabilities' view in the frontend.
        """
        PQC_SAFE = ['ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON', 'Dilithium', 'Kyber']

        vulnerable_assets = [
            n for n, d in self.G.nodes(data=True)
            if d.get('node_type') == 'asset' and
               not any(p in d.get('pqc_label', '') for p in ['Fully Quantum Safe']) and
               (d.get('score', 0) or 0) < 60
        ]

        if not vulnerable_assets:
            return {'nodes': [], 'edges': []}

        # Include 1-hop neighbors of vulnerable assets
        subgraph_nodes = set(vulnerable_assets)
        for asset in vulnerable_assets:
            subgraph_nodes.update(self.G.successors(asset))

        sub = self.G.subgraph(subgraph_nodes)
        return self._serialize_graph(sub)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        """
        Export the full graph for Vis.js rendering in the frontend.

        Returns:
            {
              nodes: [...],         # Vis.js node objects
              edges: [...],         # Vis.js edge objects
              cert_reuse: [...],    # FR-17 reuse findings
              summary: {...},       # dashboard stats
            }
        """
        graph_data = self._serialize_graph(self.G)
        graph_data['cert_reuse'] = self.detect_cert_reuse()
        graph_data['summary']    = self.get_summary()
        return graph_data

    def to_json_string(self) -> str:
        """Return to_json() as a formatted JSON string."""
        return json.dumps(self.to_json(), indent=2)

    def _serialize_graph(self, graph) -> dict:
        """Convert a NetworkX graph to Vis.js-compatible nodes + edges dicts."""
        nodes = []
        for n, d in graph.nodes(data=True):
            node_type = d.get('node_type', 'unknown')
            nodes.append({
                'id':    n,
                'label': d.get('label', str(n)[:20]),
                'type':  node_type,
                'color': {
                    'background': d.get('color', '#95A5A6'),
                    'border':     '#2C3E50',
                    'highlight':  {
                        'background': d.get('color', '#95A5A6'),
                        'border':     '#F1C40F',
                    },
                },
                'font':  {'color': '#FFFFFF', 'size': 12},
                'shape': NODE_SHAPES.get(node_type, 'ellipse'),
                # Extra metadata for tooltip on hover
                'title': self._build_tooltip(n, d),
            })

        edges = []
        for u, v, d in graph.edges(data=True):
            edges.append({
                'from':   u,
                'to':     v,
                'label':  d.get('rel', ''),
                'arrows': 'to',
                'color':  {'color': '#7F8C8D', 'highlight': '#F1C40F'},
                'font':   {'size': 10, 'color': '#BDC3C7', 'align': 'middle'},
            })

        return {'nodes': nodes, 'edges': edges}

    def _build_tooltip(self, node_id: str, data: dict) -> str:
        """Build an HTML tooltip string shown on node hover in Vis.js."""
        node_type = data.get('node_type', 'unknown')
        if node_type == 'asset':
            return (
                f"<b>{node_id}</b><br>"
                f"Score: {data.get('score', 'N/A')}/100<br>"
                f"Label: {data.get('pqc_label', 'N/A')}<br>"
                f"HNDL Risk: {data.get('hndl_risk', 'N/A')}"
            )
        if node_type == 'certificate':
            return f"<b>Certificate</b><br>Fingerprint: {data.get('full_fp', node_id)}"
        if node_type == 'ca':
            return f"<b>Certificate Authority</b><br>{node_id}"
        if node_type == 'algorithm':
            return f"<b>Algorithm</b><br>{node_id}"
        if node_type == 'protocol':
            return f"<b>TLS Protocol</b><br>{node_id}"
        return str(node_id)

    # ── Reset ──────────────────────────────────────────────────────────────────

    def reset(self):
        """Clear the graph — call before a fresh scan batch."""
        self.G.clear()
        self._cert_to_assets.clear()
        self._algo_to_assets.clear()
        self._ca_to_certs.clear()


# ── Standalone test ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    engine = DependencyGraphEngine()

    # Simulate 4 scan results — 2 share a certificate (cert reuse)
    scan_results = [
        {
            'hostname': 'pnb.co.in',
            'cert_sha1_fingerprint': 'AABBCCDD1122334455',
            'cert_issuer': 'DigiCert Global CA',
            'cert_sig_algorithm': 'RSA-SHA256',
            'tls_version': 'TLSv1.3',
            'quantum_score': 42.5,
            'label': 'Quantum Vulnerable',
            'hndl_risk': 'HIGH',
        },
        {
            'hostname': 'netbanking.pnb.co.in',
            'cert_sha1_fingerprint': 'AABBCCDD1122334455',   # same cert → reuse!
            'cert_issuer': 'DigiCert Global CA',
            'cert_sig_algorithm': 'RSA-SHA256',
            'tls_version': 'TLSv1.3',
            'quantum_score': 42.5,
            'label': 'Quantum Vulnerable',
            'hndl_risk': 'HIGH',
        },
        {
            'hostname': 'api.pnb.co.in',
            'cert_sha1_fingerprint': 'FF001122DEADBEEF99',
            'cert_issuer': 'Let\'s Encrypt R3',
            'cert_sig_algorithm': 'ECDSA-SHA256',
            'tls_version': 'TLSv1.3',
            'quantum_score': 67.0,
            'label': 'PQC Ready',
            'hndl_risk': 'MEDIUM',
        },
        {
            'hostname': 'pqc-pilot.pnb.co.in',
            'cert_sha1_fingerprint': 'DEADBEEF00112233FF',
            'cert_issuer': 'PNB Internal CA',
            'cert_sig_algorithm': 'ML-DSA-65 [FIPS 204]',
            'tls_version': 'TLSv1.3',
            'quantum_score': 95.0,
            'label': 'Fully Quantum Safe',
            'hndl_risk': 'LOW',
        },
    ]

    engine.add_multiple(scan_results)

    print("=" * 60)
    print("GRAPH SUMMARY")
    summary = engine.get_summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\nCERTIFICATE REUSE DETECTION (FR-17)")
    reuse = engine.detect_cert_reuse()
    if reuse:
        for r in reuse:
            print(f"  ⚠ Cert {r['cert_fingerprint']} reused by: {r['assets']}")
            print(f"    → {r['risk_note']}")
    else:
        print("  No certificate reuse detected.")

    print("\nGRAPH EXPORT (node count, edge count)")
    exported = engine.to_json()
    print(f"  Nodes: {len(exported['nodes'])}")
    print(f"  Edges: {len(exported['edges'])}")
    print(f"  Cert reuse findings: {len(exported['cert_reuse'])}")

    print("\nVULNERABLE SUBGRAPH")
    vsub = engine.get_vulnerable_subgraph()
    print(f"  Nodes in vulnerable subgraph: {len(vsub['nodes'])}")
    print(f"  Edges in vulnerable subgraph: {len(vsub['edges'])}")

    print("\n✅ dep_graph.py OK")