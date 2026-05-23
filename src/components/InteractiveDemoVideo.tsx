import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Brain, Send, Shield, AlertTriangle, CheckCircle, Activity, MessageSquare } from "lucide-react";

const InteractiveDemoVideo = () => {
  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);
  const [userMessage, setUserMessage] = useState("");
  const [showTyping, setShowTyping] = useState(false);
  const [userInput, setUserInput] = useState("");
  const [isUserInteracting, setIsUserInteracting] = useState(false);
  const [chatHistory, setChatHistory] = useState([]);

  const demoSteps = [
    {
      userMessage: "SouHimBou, analyze current threat landscape",
      aiResponse: "Scanning global threat intelligence feeds... Detected 47 active campaigns. Prioritizing by risk score.",
      actions: ["threat_scan", "intelligence_analysis"],
      metrics: { threats: 47, blocked: 2847, risk: "Medium" }
    },
    {
      userMessage: "Show me the Beijing APT campaign details",
      aiResponse: "Beijing APT-29 variant detected. Analyzing attack vectors... Implementing countermeasures for zero-day exploitation attempt.",
      actions: ["detailed_analysis", "countermeasures"],
      metrics: { threats: 52, blocked: 2851, risk: "High" }
    },
    {
      userMessage: "Activate automated response protocols",
      aiResponse: "Automated response activated. Isolating infected endpoints... Updating firewall rules... Threat neutralized in 2.3 seconds.",
      actions: ["auto_response", "isolation", "firewall_update"],
      metrics: { threats: 46, blocked: 2852, risk: "Low" }
    }
  ];

  useEffect(() => {
    if (!isPlaying || isUserInteracting) return;

    const timer = setInterval(() => {
      setCurrentStep((prev) => (prev + 1) % demoSteps.length);
    }, 6000);

    return () => clearInterval(timer);
  }, [isPlaying, isUserInteracting, demoSteps.length]);

  useEffect(() => {
    if (isUserInteracting) return;
    
    const step = demoSteps[currentStep];
    setUserMessage("");
    setShowTyping(false);

    // Simulate typing user message
    const typeUserMessage = () => {
      let i = 0;
      const typing = setInterval(() => {
        if (i < step.userMessage.length) {
          setUserMessage(step.userMessage.slice(0, i + 1));
          i++;
        } else {
          clearInterval(typing);
          setTimeout(() => setShowTyping(true), 500);
        }
      }, 50);
    };

    setTimeout(typeUserMessage, 1000);
  }, [currentStep, isUserInteracting]);

  const handleUserInput = (e) => {
    e.preventDefault();
    if (!userInput.trim()) return;

    // Switch to interactive mode
    setIsUserInteracting(true);
    setIsPlaying(false);

    // Add user message to chat history
    const newUserMessage = { type: 'user', content: userInput, timestamp: new Date() };
    setChatHistory(prev => [...prev, newUserMessage]);

    // Generate AI response
    const aiResponse = generateAIResponse(userInput);
    setTimeout(() => {
      const newAIMessage = { 
        type: 'ai', 
        content: aiResponse.response, 
        actions: aiResponse.actions,
        timestamp: new Date() 
      };
      setChatHistory(prev => [...prev, newAIMessage]);
    }, 1000);

    setUserInput("");
  };

  const generateAIResponse = (input) => {
    const responses = [
      {
        response: "Analyzing your request... Scanning threat intelligence feeds and cross-referencing with global security databases.",
        actions: ["threat_analysis", "intelligence_scan"]
      },
      {
        response: "Security protocols activated. Implementing multi-layer defense strategies and updating firewall configurations.",
        actions: ["security_update", "firewall_config"]
      },
      {
        response: "Threat assessment complete. Identified potential vulnerabilities and recommending immediate remediation steps.",
        actions: ["vulnerability_scan", "remediation_plan"]
      },
      {
        response: "Real-time monitoring enabled. Continuous threat detection active with automated response capabilities.",
        actions: ["real_time_monitor", "auto_response"]
      }
    ];
    
    // Deterministic selection based on input length — no random fabrication
    return responses[input.length % responses.length];
  };

  const currentData = demoSteps[currentStep];

  return (
    <div className="relative bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 rounded-xl border border-blue-500/30 overflow-hidden">
      {/* Video Controls */}
      <div className="absolute top-4 right-4 z-20 flex items-center space-x-2">
        <Button
          size="sm"
          variant="outline"
          onClick={() => setIsPlaying(!isPlaying)}
          className="bg-black/60 border-blue-500/30 text-blue-400 hover:bg-blue-500/20"
        >
          {isPlaying ? "Pause" : "Play"} Demo
        </Button>
      </div>

      {/* Demo Interface */}
      <div className="p-6 min-h-[500px] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Brain className="h-8 w-8 text-purple-400" />
              <div className="absolute -top-1 -right-1 h-3 w-3 bg-green-400 rounded-full animate-pulse"></div>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">SouHimBou AI Agent</h3>
              <p className="text-xs text-green-400">Powered by GrokAI • Online</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-sm text-gray-300">Live Demo</div>
            <div className="text-xs text-blue-400">Interactive Session</div>
          </div>
        </div>

        {/* Metrics Dashboard */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-black/40 rounded-lg p-3 border border-green-500/30">
            <div className="flex items-center space-x-2">
              <Shield className="h-4 w-4 text-green-400" />
              <span className="text-xs text-gray-400">Threats Blocked</span>
            </div>
            <div className="text-lg font-bold text-green-400">{currentData.metrics.blocked.toLocaleString()}</div>
          </div>
          <div className="bg-black/40 rounded-lg p-3 border border-orange-500/30">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              <span className="text-xs text-gray-400">Active Threats</span>
            </div>
            <div className="text-lg font-bold text-orange-400">{currentData.metrics.threats}</div>
          </div>
          <div className="bg-black/40 rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center space-x-2">
              <Activity className="h-4 w-4 text-blue-400" />
              <span className="text-xs text-gray-400">Risk Level</span>
            </div>
            <div className={`text-lg font-bold ${
              currentData.metrics.risk === 'High' ? 'text-red-400' :
              currentData.metrics.risk === 'Medium' ? 'text-orange-400' : 'text-green-400'
            }`}>
              {currentData.metrics.risk}
            </div>
          </div>
        </div>

        {/* Chat Interface */}
        <div className="flex-1 bg-black/30 rounded-lg border border-blue-500/20 p-4 mb-4">
          <div className="space-y-4 h-48 overflow-y-auto">
            {isUserInteracting ? (
              // Interactive Chat History
              chatHistory.map((message, index) => (
                <div key={index} className={`flex ${message.type === 'user' ? 'justify-end' : 'items-start space-x-3'}`}>
                  {message.type === 'user' ? (
                    <div className="bg-blue-600 text-white rounded-lg px-4 py-2 max-w-xs">
                      <div className="text-sm">{message.content}</div>
                      <div className="text-xs text-blue-200 mt-1">You • Now</div>
                    </div>
                  ) : (
                    <>
                      <Brain className="h-6 w-6 text-purple-400 mt-1" />
                      <div className="bg-gray-800 text-white rounded-lg px-4 py-2 max-w-md">
                        <div className="text-sm">{message.content}</div>
                        <div className="text-xs text-gray-400 mt-1">SouHimBou AI • Now</div>
                        
                        {/* Action Indicators */}
                        {message.actions && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {message.actions.map((action, actionIndex) => (
                              <span 
                                key={actionIndex}
                                className="text-xs bg-purple-600/30 text-purple-300 px-2 py-1 rounded border border-purple-500/30"
                              >
                                {action.replaceAll('_', ' ')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              ))
            ) : (
              // Automated Demo Chat
              <>
                {/* User Message */}
                <div className="flex justify-end">
                  <div className="bg-blue-600 text-white rounded-lg px-4 py-2 max-w-xs">
                    <div className="text-sm">{userMessage}</div>
                    {userMessage && <div className="text-xs text-blue-200 mt-1">You • Now</div>}
                  </div>
                </div>

                {/* AI Response */}
                {showTyping && (
                  <div className="flex items-start space-x-3">
                    <Brain className="h-6 w-6 text-purple-400 mt-1" />
                    <div className="bg-gray-800 text-white rounded-lg px-4 py-2 max-w-md">
                      <div className="text-sm">{currentData.aiResponse}</div>
                      <div className="text-xs text-gray-400 mt-1">SouHimBou AI • Now</div>
                      
                      {/* Action Indicators */}
                      <div className="flex flex-wrap gap-1 mt-2">
                        {currentData.actions.map((action, index) => (
                          <span 
                            key={action}
                            className="text-xs bg-purple-600/30 text-purple-300 px-2 py-1 rounded border border-purple-500/30"
                          >
                            {action.replaceAll('_', ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Input Interface */}
        <form onSubmit={handleUserInput} className="flex items-center space-x-3">
          <div className="flex-1">
            <input
              type="text"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              placeholder={isUserInteracting ? "Type your command here..." : "Try typing here to interact!"}
              className="w-full bg-black/40 border border-blue-500/30 rounded-lg px-4 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 transition-colors"
            />
          </div>
          <Button 
            type="submit"
            size="sm" 
            className="bg-purple-600 hover:bg-purple-700"
            disabled={!userInput.trim()}
          >
            <Send className="h-4 w-4" />
          </Button>
        </form>

        {/* Progress Indicator */}
        <div className="flex justify-center mt-4 space-x-2">
          {demoSteps.map((_, index) => (
            <div
              key={index}
              className={`h-2 w-2 rounded-full transition-all duration-300 ${
                index === currentStep ? 'bg-blue-400' : 'bg-gray-600'
              }`}
            />
          ))}
        </div>
      </div>

      {/* Overlay Effects */}
      <div className="absolute inset-0 bg-gradient-to-t from-blue-600/5 to-transparent pointer-events-none" />
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-purple-500 animate-pulse" />
    </div>
  );
};

export default InteractiveDemoVideo;