import { useRef, useEffect } from "react";
import ForceGraph3D from "react-force-graph-3d";
import * as THREE from "three";

interface DAGNode {
    id: string;
    label: string;
    type: string;
    status: string;
}

interface DAGEdge {
    source: string;
    target: string;
    type: string;
}

interface TrustConstellationProps {
    nodes: DAGNode[];
    edges: DAGEdge[];
    onNodeClick?: (node: DAGNode) => void;
}

const TrustConstellation3D = ({ nodes, edges, onNodeClick }: TrustConstellationProps) => {
    const fgRef = useRef<any>();

    useEffect(() => {
        // Auto-rotate camera for dramatic effect
        if (fgRef.current) {
            fgRef.current.cameraPosition({ z: 400 });

            // Gentle rotation
            const interval = setInterval(() => {
                if (fgRef.current) {
                    const camera = fgRef.current.camera();
                    const angle = Date.now() * 0.0001;
                    camera.position.x = 400 * Math.sin(angle);
                    camera.position.z = 400 * Math.cos(angle);
                    camera.lookAt(0, 0, 0);
                }
            }, 50);

            return () => clearInterval(interval);
        }
    }, []);

    // Color mapping based on node status
    const getNodeColor = (node: DAGNode) => {
        switch (node.status?.toLowerCase()) {
            case "critical":
                return "#ef4444"; // red
            case "pending":
            case "warn":
                return "#f59e0b"; // orange
            case "immutable":
            case "pass":
                return "#10b981"; // green
            default:
                return "#6366f1"; // indigo
        }
    };

    // Node size based on type
    const getNodeSize = (node: DAGNode) => {
        switch (node.type?.toLowerCase()) {
            case "block":
            case "genesis":
                return 8;
            case "scan":
            case "finding":
                return 6;
            default:
                return 4;
        }
    };

    // Custom node rendering with Three.js
    const nodeThreeObject = (node: any) => {
        const color = getNodeColor(node);
        const size = getNodeSize(node);

        // Create a glowing sphere
        const geometry = new THREE.SphereGeometry(size, 16, 16);
        const material = new THREE.MeshBasicMaterial({
            color: color,
            transparent: true,
            opacity: 0.9,
        });
        const mesh = new THREE.Mesh(geometry, material);

        // Add glow effect
        const glowGeometry = new THREE.SphereGeometry(size * 1.3, 16, 16);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: color,
            transparent: true,
            opacity: 0.3,
        });
        const glow = new THREE.Mesh(glowGeometry, glowMaterial);
        mesh.add(glow);

        // Add label
        const sprite = new THREE.Sprite(
            new THREE.SpriteMaterial({
                map: createTextTexture(node.label || node.id),
                transparent: true,
            })
        );
        sprite.scale.set(20, 10, 1);
        sprite.position.y = size + 5;
        mesh.add(sprite);

        return mesh;
    };

    // Create text texture for labels
    const createTextTexture = (text: string) => {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d");
        if (!context) return new THREE.Texture();

        canvas.width = 256;
        canvas.height = 128;

        context.fillStyle = "#ffffff";
        context.font = "bold 24px Arial";
        context.textAlign = "center";
        context.textBaseline = "middle";
        context.fillText(text.substring(0, 20), 128, 64);

        const texture = new THREE.Texture(canvas);
        texture.needsUpdate = true;
        return texture;
    };

    // Link color based on type
    const getLinkColor = (link: any) => {
        switch (link.type?.toLowerCase()) {
            case "cause":
                return "#ef4444";
            case "mitigation":
                return "#10b981";
            case "parent":
                return "#6366f1";
            default:
                return "#64748b";
        }
    };

    return (
        <div className="w-full h-full bg-slate-950 rounded-lg overflow-hidden">
            <ForceGraph3D
                ref={fgRef}
                graphData={{ nodes, links: edges }}
                nodeLabel={(node: any) => `${node.label || node.id}\n${node.type} - ${node.status}`}
                nodeColor={getNodeColor}
                nodeVal={getNodeSize}
                nodeThreeObject={nodeThreeObject}
                linkColor={getLinkColor}
                linkWidth={2}
                linkDirectionalArrowLength={3}
                linkDirectionalArrowRelPos={1}
                linkOpacity={0.6}
                onNodeClick={(node: any) => onNodeClick?.(node as DAGNode)}
                backgroundColor="#020617"
                showNavInfo={false}
                enableNodeDrag={true}
                enableNavigationControls={true}
            />
        </div>
    );
};

export default TrustConstellation3D;
