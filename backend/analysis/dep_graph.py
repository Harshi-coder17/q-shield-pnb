import networkx as nx
import json
from collections import defaultdict
 
NODE_COLORS = {
    'asset':       '#2471A3',
    'certificate': '#27AE60',
    'ca':          '#D4AC0D',
    'algorithm':   '#E74C3C',
    'protocol':    '#8E44AD',
}
 
class DependencyGraphEngine:
    def __init__(self):
        self.G = nx.DiGraph()
        self._cert_to_assets = defaultdict(list)
 
    def add_scan_result(self, scan_data: dict):
        host     = scan_data.get('hostname', 'unknown')
        cert_fp  = scan_data.get('cert_sha1_fp') or scan_data.get('cert_sha1_fingerprint', 'unknown_cert')
        cert_fp  = cert_fp[:20] if cert_fp else 'unknown_cert'
        issuer   = scan_data.get('cert_issuer', 'Unknown CA')
        alg      = scan_data.get('cert_sig_algorithm', 'Unknown Alg')
        proto    = scan_data.get('tls_version', 'Unknown TLS')
        score    = scan_data.get('quantum_score', 0)
        label    = scan_data.get('label', 'Unknown')
 
        if   score and score >= 90: node_color = '#27AE60'
        elif score and score >= 60: node_color = '#F39C12'
        elif score and score >= 30: node_color = '#E74C3C'
        else:                       node_color = '#1C2833'
 
        self.G.add_node(host,    node_type='asset',       label=host,              color=node_color, score=score, pqc_label=label)
        self.G.add_node(cert_fp, node_type='certificate', label=f'Cert:{cert_fp[:8]}', color=NODE_COLORS['certificate'])
        self.G.add_node(issuer,  node_type='ca',          label=issuer[:30],       color=NODE_COLORS['ca'])
        self.G.add_node(alg,     node_type='algorithm',   label=alg[:25],          color=NODE_COLORS['algorithm'])
        self.G.add_node(proto,   node_type='protocol',    label=proto,             color=NODE_COLORS['protocol'])
 
        self.G.add_edge(host,    cert_fp, rel='uses_certificate')
        self.G.add_edge(cert_fp, alg,     rel='signed_with')
        self.G.add_edge(cert_fp, issuer,  rel='issued_by')
        self.G.add_edge(host,    proto,   rel='communicates_via')
 
        if host not in self._cert_to_assets[cert_fp]:
            self._cert_to_assets[cert_fp].append(host)
 
    def detect_cert_reuse(self) -> list:
        """FR-17: Find certificates shared across multiple assets."""
        return [{'cert_fingerprint': cert, 'assets': assets, 'reuse_count': len(assets)}
                for cert, assets in self._cert_to_assets.items() if len(assets) > 1]
 
    def to_json(self) -> dict:
        """Export for Vis.js rendering in the frontend."""
        nodes = []
        for n, d in self.G.nodes(data=True):
            nodes.append({'id': n, 'label': d.get('label', str(n)[:20]),
                          'type': d.get('node_type', 'unknown'),
                          'color': {'background': d.get('color', '#95A5A6'), 'border': '#2C3E50'},
                          'font': {'color': '#FFFFFF', 'size': 12},
                          'shape': 'ellipse' if d.get('node_type') == 'asset' else 'box'})
        edges = []
        for u, v, d in self.G.edges(data=True):
            edges.append({'from': u, 'to': v, 'label': d.get('rel', ''),
                          'arrows': 'to', 'color': {'color': '#7F8C8D'}})
        return {'nodes': nodes, 'edges': edges, 'cert_reuse': self.detect_cert_reuse()}
