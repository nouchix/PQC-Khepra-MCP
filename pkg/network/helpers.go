package network

import (
	"fmt"
	"strings"
)

// HostCount returns the number of hosts in the topology
func (nt *NetworkTopology) HostCount() int {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return len(nt.hosts)
}

// ConnectionCount returns the number of connections
func (nt *NetworkTopology) ConnectionCount() int {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return len(nt.connections)
}

// Summary generates a text summary of an attack path
func (ap *AttackPath) Summary() string {
	if len(ap.Steps) == 0 {
		return "No steps"
	}

	// Get source and destination
	source := ap.Steps[0].FromHost
	dest := ap.Steps[len(ap.Steps)-1].ToHost

	return fmt.Sprintf("%s → %s (%d hops)", source, dest, len(ap.Steps))
}

// GenerateD3Visualization creates an HTML file with D3.js network graph
func (nt *NetworkTopology) GenerateD3Visualization() string {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	// Build nodes array
	var nodes []string
	nodeIndex := make(map[string]int)
	i := 0
	for hostID, host := range nt.hosts {
		color := "#3498db" // Default blue
		// Criticality is int 1-5 (5 = most critical)
		switch host.Criticality {
		case 5:
			color = "#e74c3c" // Red (CRITICAL)
		case 4:
			color = "#e67e22" // Orange (HIGH)
		case 3:
			color = "#f39c12" // Yellow (MEDIUM)
		case 2:
			color = "#3498db" // Blue (LOW)
		case 1:
			color = "#95a5a6" // Gray (INFO)
		}

		nodes = append(nodes, fmt.Sprintf(`{id: "%s", label: "%s", color: "%s"}`,
			hostID, host.Hostname, color))
		nodeIndex[hostID] = i
		i++
	}

	// Build edges array
	var edges []string
	for _, conn := range nt.connections {
		sourceIdx, ok1 := nodeIndex[conn.SourceHost]
		destIdx, ok2 := nodeIndex[conn.DestHost]
		if !ok1 || !ok2 {
			continue
		}

		edges = append(edges, fmt.Sprintf(`{source: %d, target: %d, label: "%s"}`,
			sourceIdx, destIdx, conn.Protocol))
	}

	// Generate HTML
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Khepra Network Attack Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; background: #1a1a1a; }
        #graph { width: 100vw; height: 100vh; }
        .node { cursor: pointer; }
        .node circle { stroke: #fff; stroke-width: 2px; }
        .node text { fill: #fff; font-size: 12px; text-anchor: middle; }
        .link { stroke: #666; stroke-width: 2px; opacity: 0.6; }
        .link-label { fill: #ccc; font-size: 10px; }
        #info {
            position: absolute; top: 20px; right: 20px;
            background: rgba(0,0,0,0.8); color: #fff;
            padding: 15px; border-radius: 5px;
            max-width: 300px;
        }
    </style>
</head>
<body>
    <svg id="graph"></svg>
    <div id="info">
        <h3>Khepra Attack Graph</h3>
        <p>Nodes: ` + fmt.Sprintf("%d", len(nodes)) + `</p>
        <p>Connections: ` + fmt.Sprintf("%d", len(edges)) + `</p>
        <p><strong>Legend:</strong></p>
        <p style="color:#e74c3c">● CRITICAL</p>
        <p style="color:#e67e22">● HIGH</p>
        <p style="color:#f39c12">● MEDIUM</p>
        <p style="color:#3498db">● LOW</p>
    </div>
    <script>
        const nodes = [` + strings.Join(nodes, ",\n            ") + `];
        const links = [` + strings.Join(edges, ",\n            ") + `];

        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#graph")
            .attr("width", width)
            .attr("height", height);

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).distance(150))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("class", "link");

        const node = svg.append("g")
            .selectAll("g")
            .data(nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        node.append("circle")
            .attr("r", 15)
            .attr("fill", d => d.color);

        node.append("text")
            .attr("dy", 25)
            .text(d => d.label);

        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
        });

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    </script>
</body>
</html>`

	return html
}
