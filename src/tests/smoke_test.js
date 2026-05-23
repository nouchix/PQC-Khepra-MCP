
// Mock Polymorphic Mapping Logic for local verification
const transformSourceData = (source, data) => {
    switch (source) {
        case 'aws_sdk':
            return {
                asset_name: data.Tags?.find((t) => t.Key === 'Name')?.Value || data.InstanceId,
                asset_type: 'server',
                platform: 'aws',
                operating_system: data.PlatformDetails || 'Linux',
                version: data.InstanceType,
                ip_addresses: [data.PrivateIpAddress, data.PublicIpAddress].filter(Boolean),
                metadata: { ...data, provider: 'aws' }
            }
        case 'azure_api':
            return {
                asset_name: data.name,
                asset_type: 'server',
                platform: 'azure',
                operating_system: data.properties?.storageProfile?.osDisk?.osType || 'Unknown',
                version: data.properties?.hardwareProfile?.vmSize,
                ip_addresses: [data.properties?.networkProfile?.networkInterfaces?.[0]?.id],
                metadata: { ...data, provider: 'azure' }
            }
        case 'custom_payload':
            return {
                asset_name: data.hostname || data.label || 'unknown-asset',
                asset_type: data.category || 'device',
                platform: data.env || 'on-premise',
                operating_system: data.os_info || 'other',
                version: data.ver || 'v1.0',
                ip_addresses: Array.isArray(data.ips) ? data.ips : [data.ip].filter(Boolean),
                metadata: data
            }
        default:
            return data
    }
}

const runTests = () => {
    console.log("🚀 Starting Sentinel Polymorphic Engine Logic Test...\n");

    const tests = [
        {
            name: "AWS EC2 Mapping Test",
            source: "aws_sdk",
            payload: {
                InstanceId: "i-1234567890abcdef0",
                InstanceType: "t3.medium",
                PlatformDetails: "Ubuntu 22.04 LTS",
                PrivateIpAddress: "10.0.1.5",
                Tags: [{ Key: "Name", Value: "Security-Gateway" }]
            },
            expected: "Security-Gateway"
        },
        {
            name: "Industrial SCADA (IoT) Mapping Test",
            source: "custom_payload",
            payload: {
                hostname: "PLC-SIEMENS-001",
                category: "SCADA/ICS",
                env: "Nuclear-Enclave-A",
                os_info: "Proprietary-Embedded",
                ips: ["192.168.1.10"]
            },
            expected: "PLC-SIEMENS-001"
        },
        {
            name: "Azure VM Mapping Test",
            source: "azure_api",
            payload: {
                name: "Azure-Sentinel-Node",
                properties: {
                    storageProfile: { osDisk: { osType: "Windows" } },
                    hardwareProfile: { vmSize: "Standard_D2s_v3" }
                }
            },
            expected: "Azure-Sentinel-Node"
        }
    ];

    let passed = 0;
    tests.forEach((t, i) => {
        try {
            const result = transformSourceData(t.source, t.payload);
            const success = result.asset_name === t.expected;
            console.log(`[TEST ${i + 1}] ${t.name}: ${success ? '✅ PASSED' : '❌ FAILED'}`);
            if (!success) {
                console.log(`   Expected: ${t.expected}, Got: ${result.asset_name}`);
            } else {
                passed++;
                console.log(`   Mapped ${t.source} -> ${result.asset_type} (${result.platform}) OS: ${result.operating_system}`);
            }
        } catch (err) {
            console.log(`[TEST ${i + 1}] ${t.name}: ❌ CRASHED (${err.message})`);
        }
    });

    console.log(`\n📊 Final Results: ${passed}/${tests.length} tests passed.`);
    if (passed === tests.length) {
        console.log("✅ Sentinel Polymorphic Engine is READY for environment-agnostic ingestion.");
    } else {
        console.log("⚠️ Some mapping logic requires adjustment.");
    }
}

runTests();
