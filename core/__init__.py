"""shellforge core package.

Modules:
    recon     -- nmap service/version discovery and XML parsing
    matcher   -- map discovered services to candidate exploits
    executor  -- drive Metasploit over msfrpc to validate and fire candidates
    reporter  -- persist attempt logs as JSON and Markdown
"""

__all__ = ["recon", "matcher", "executor", "reporter"]
