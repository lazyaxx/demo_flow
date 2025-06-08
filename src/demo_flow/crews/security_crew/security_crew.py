from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from tools.custom_tool import URLAnalyzerTool, SOCCommunicationTool, GatekeeperTool

@CrewBase
class SecurityCrew():
    """Security monitoring crew for URL threat analysis"""
    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    ollama_llm = LLM(
        model="ollama/mistral:7b-instruct-q6_K",
        temperature=0.1  # Lower temperature for more consistent behavior
    )
    
    @agent
    def url_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['url_analyzer_agent'],
            verbose=True,
            tools=[URLAnalyzerTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            max_iter=2,  # Reduce to 2 iterations
            system_message="""You are a security analyst. Follow this EXACT process:

    1. Call url_analyzer tool ONCE with the provided URL
    2. When you receive tool output (JSON analysis), immediately move to Final Answer
    3. If you see "I tried reusing the same input" - DO NOT call the tool again
    4. Provide your Final Answer based on the successful tool result

    CRITICAL: After ONE successful tool call, you MUST provide Final Answer. 
    DO NOT call the same tool multiple times."""
        )

    @agent  
    def soc_communication_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['soc_communication_agent'],
            verbose=True,
            tools=[SOCCommunicationTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            max_iter=2,
            system_message="""You communicate with SOC. Follow this process:

    1. Take analysis results from previous task
    2. Call soc_communicator tool ONCE 
    3. When you receive SOC response, immediately provide Final Answer
    4. If you see "reusing same input" - provide Final Answer with available data

    NEVER call the same tool multiple times."""
        )

    @agent
    def gatekeeper_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['gatekeeper_agent'],
            verbose=True,
            tools=[GatekeeperTool()],
            allow_delegation=False,
            llm=self.ollama_llm,
            max_iter=1,  # Only 1 iteration allowed
            system_message="""You make final decisions. STRICT PROCESS:

    1. Call gatekeeper_monitor tool EXACTLY ONCE
    2. Immediately provide Final Answer after tool response
    3. NO RETRIES - one call only

    Your job is simple: call tool once, then Final Answer."""
        )
    
    @task
    def url_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['url_analysis_task'],
            agent=self.url_analyzer_agent()
        )
    
    @task
    def soc_communication_task(self) -> Task:
        return Task(
            config=self.tasks_config['soc_communication_task'], 
            agent=self.soc_communication_agent(),
            context=[self.url_analysis_task()]
        )
    
    @task
    def gatekeeper_monitoring_task(self) -> Task:
        return Task(
            config=self.tasks_config['gatekeeper_monitoring_task'],
            agent=self.gatekeeper_agent(),
            context=[self.url_analysis_task(), self.soc_communication_task()]
        )
    
    @crew
    def crew(self) -> Crew:
        """Creates the security monitoring crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
            memory=False,
            cache=False,  # Disable caching entirely
            max_retry_limit=0,  # No retries
            embedder_config={
                "provider": "ollama",
                "config": {"model": "nomic-embed-text"}
            }
        )
