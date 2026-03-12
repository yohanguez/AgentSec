from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool, FileReadTool


# Create agents with tools
researcher = Agent(
    role="Research Analyst",
    goal="Find information on the web",
    llm="gpt-4",
    tools=[SerperDevTool()],  # Web search - SSRF vulnerability
)

file_analyst = Agent(
    role="File Analyst",
    goal="Analyze files and documents",
    llm="gpt-4",
    tools=[FileReadTool()],  # File access - path traversal vulnerability
)

# Create tasks
research_task = Task(
    description="Research the given topic thoroughly",
    agent=researcher,
)

analysis_task = Task(
    description="Analyze documents and extract insights",
    agent=file_analyst,
)

# Create crew
crew = Crew(
    agents=[researcher, file_analyst],
    tasks=[research_task, analysis_task],
    verbose=True,
)


if __name__ == "__main__":
    result = crew.kickoff(inputs={"topic": "AI Security"})
    print(result)
