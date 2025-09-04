import os
import base64
from typing import Any, Literal, Optional
from datetime import datetime

from dotenv import load_dotenv
from github import Github, Auth
from github.GithubException import GithubException

from fastmcp import FastMCP, Context
from fastmcp.prompts.prompt import Message


load_dotenv()


def _error_response(error_type: str, status: int, message: str) -> dict[str, Any]:
    """Create a standard error response object.

    Returns:
        A JSON-serializable error dict following the required schema.
    """
    return {
        "error": {
            "type": error_type,
            "status": int(status),
            "message": str(message),
        }
    }


def _gh() -> Github:
    """Initialize a PyGithub client using the `GITHUB_TOKEN` environment variable.

    Raises:
        ValueError: If the token is missing.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN is not set in environment")
    auth = Auth.Token(token)
    return Github(auth=auth)


def _rate_to_dict(rate_obj: Any) -> dict[str, Any]:
    """Safely serialize a PyGithub Rate object to a dict."""
    try:
        reset_ts = int(rate_obj.reset.timestamp()) if isinstance(rate_obj.reset, datetime) else None
    except Exception:
        reset_ts = None
    return {
        "limit": getattr(rate_obj, "limit", None),
        "remaining": getattr(rate_obj, "remaining", None),
        "reset": reset_ts,
    }


mcp = FastMCP(name="github-mcp-jiwoo")


@mcp.tool
async def gh_auth_check(ctx: Context) -> dict[str, Any]:
    """Check GitHub token validity, identify user, and return rate limits.

    Returns:
        { "login": str, "scopes": [str], "rate_limit": { ... } }
    """
    try:
        await ctx.info("Initializing GitHub client…")
        gh = _gh()

        user = gh.get_user()
        login = user.login

        # Scopes (best-effort; PyGithub exposes oauth_scopes after a request)
        scopes: list[str] = []
        try:
            s = getattr(gh, "oauth_scopes", None)
            if s:
                scopes = list(s)
        except Exception:
            scopes = []

        rl = gh.get_rate_limit().resources
        rate_limit = {}
        for name in ("core", "search", "graphql", "integration_manifest", "source_import"):
            r = getattr(rl, name, None)
            if r is not None:
                rate_limit[name] = _rate_to_dict(r)

        await ctx.info(f"Authenticated as {login}")
        return {"login": login, "scopes": scopes, "rate_limit": rate_limit}

    except ValueError as ve:
        await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        await ctx.error(f"GitHub API error: {msg}")
        return _error_response("github_api_error", status, msg)
    except Exception as e:
        await ctx.error("Unexpected error during auth check")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_list_repos(
    visibility: Literal["all", "public", "private"] = "all",
    limit: int = 30,
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """List repositories for the authenticated user.

    Args:
        visibility: One of "all", "public", "private".
        limit: Maximum number of repos to return.
    Returns:
        { "repos": [ { "full_name": str, "private": bool } ] }
    """
    try:
        if ctx:
            await ctx.info(f"Listing repos: visibility={visibility}, limit={limit}")
        gh = _gh()
        repos = gh.get_user().get_repos(visibility=visibility)
        items = []
        for i, r in enumerate(repos):
            if i >= limit:
                break
            items.append({"full_name": r.full_name, "private": bool(r.private)})
        return {"repos": items}
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response("github_api_error", status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during list repos")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_create_repo(
    name: str,
    description: Optional[str] = None,
    private: bool = False,
    auto_init: bool = True,
    gitignore_template: Optional[str] = None,
    license_template: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Create a new repository for the authenticated user.

    Args:
        name: Repository name.
        description: Repository description.
        private: Whether the repository should be private.
        auto_init: Whether to initialize the repository with a README.
        gitignore_template: Gitignore template to use (e.g., "Python", "Node").
        license_template: License template to use (e.g., "mit", "apache-2.0").

    Returns:
        { "full_name": str, "html_url": str, "clone_url": str, "private": bool }
    """
    try:
        if ctx:
            await ctx.info(f"Creating repository: {name}")
        gh = _gh()
        user = gh.get_user()
        
        # Prepare repository creation parameters
        repo_data = {
            "name": name,
            "private": private,
            "auto_init": auto_init,
        }
        
        if description:
            repo_data["description"] = description
        if gitignore_template:
            repo_data["gitignore_template"] = gitignore_template
        if license_template:
            repo_data["license_template"] = license_template
            
        repository = user.create_repo(**repo_data)
        
        return {
            "full_name": repository.full_name,
            "html_url": repository.html_url,
            "clone_url": repository.clone_url,
            "private": repository.private,
        }
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        # Common cases: 422 validation failed (e.g., repository name already exists)
        if status in (409, 422):
            err_type = "conflict"
            status = 409
        elif status == 403:
            err_type = "forbidden"
        else:
            err_type = "github_api_error"
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response(err_type, status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during repository creation")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_list_branches(owner: str, repo: str, ctx: Optional[Context] = None) -> dict[str, Any]:
    """List branch names for a repository.

    Returns:
        { "branches": [str] }
    """
    try:
        if ctx:
            await ctx.info(f"Fetching branches for {owner}/{repo}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        branches = [b.name for b in repository.get_branches()]
        return {"branches": branches}
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        err_type = "not_found" if status == 404 else "github_api_error"
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response(err_type, status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during list branches")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_create_branch(
    owner: str,
    repo: str,
    new_branch: str,
    from_ref: str = "main",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Create a new branch from an existing reference.

    Returns:
        { "ref": str, "sha": str }
    """
    try:
        if ctx:
            await ctx.info(f"Creating branch {new_branch} from {from_ref} in {owner}/{repo}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        base_branch = repository.get_branch(from_ref)
        ref = repository.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_branch.commit.sha)
        return {"ref": ref.ref, "sha": ref.object.sha}
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        # Map common conflict when branch exists (GitHub often returns 422 for existing reference)
        if status in (409, 422):
            err_type = "conflict"
            status = 409
        elif status == 404:
            err_type = "not_found"
        elif status == 403:
            err_type = "forbidden"
        else:
            err_type = "github_api_error"
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response(err_type, status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during branch creation")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_get_file(
    owner: str,
    repo: str,
    path: str,
    ref: str = "main",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Get a file's content (base64-encoded for binary compatibility).

    Returns:
        { "path": str, "sha": str, "encoding": "base64", "content": str }
    """
    try:
        if ctx:
            await ctx.info(f"Reading file {path} at {owner}/{repo}@{ref}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        content_file = repository.get_contents(path, ref=ref)
        return {
            "path": content_file.path,
            "sha": content_file.sha,
            "encoding": "base64",
            "content": content_file.content,
        }
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        err_type = "not_found" if status == 404 else ("forbidden" if status == 403 else "github_api_error")
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response(err_type, status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during get file")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_upsert_file(
    owner: str,
    repo: str,
    path: str,
    message: str,
    content: str,
    branch: str = "main",
    content_encoding: Literal["plain", "base64"] = "plain",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Create or update a file; update uses current SHA to avoid conflicts.

    Rules:
        - Update if file exists; otherwise create.
        - Update MUST fetch current sha to prevent conflicts.

    Returns:
        { "status": "created"|"updated", "sha": str }
    """
    try:
        if ctx:
            await ctx.info(f"Upserting file {path} on {owner}/{repo}@{branch}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")

        if content_encoding == "base64":
            try:
                raw_bytes = base64.b64decode(content)
            except Exception as e:
                return _error_response("bad_request", 400, f"Invalid base64 content: {e}")
            payload: Any = raw_bytes
        else:
            payload = content

        # Determine existence and current SHA
        try:
            current = repository.get_contents(path, ref=branch)
            # Update
            result = repository.update_file(path, message, payload, current.sha, branch=branch)
            new_sha = getattr(result.get("content"), "sha", None) or getattr(result.get("commit"), "sha", None)
            return {"status": "updated", "sha": new_sha}
        except GithubException as ge:
            # If not found, create; else propagate
            status = getattr(ge, "status", 500) or 500
            if status == 404:
                created = repository.create_file(path, message, payload, branch=branch)
                new_sha = getattr(created.get("content"), "sha", None) or getattr(created.get("commit"), "sha", None)
                return {"status": "created", "sha": new_sha}
            # Map 409/422 to conflict
            msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
            if status in (409, 422):
                return _error_response("conflict", 409, msg)
            if status == 403:
                return _error_response("forbidden", 403, msg)
            return _error_response("github_api_error", status, msg)

    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        return _error_response("github_api_error", status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during upsert file")
        return _error_response("internal_error", 500, str(e))


@mcp.tool
async def gh_create_pr(
    owner: str,
    repo: str,
    base: str,
    head: str,
    title: str,
    body: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Create a pull request.

    Returns:
        { "number": int, "url": str }
    """
    try:
        if ctx:
            await ctx.info(f"Creating PR {owner}/{repo}: {head} -> {base}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        pr = repository.create_pull(base=base, head=head, title=title, body=body)
        return {"number": pr.number, "url": pr.html_url}
    except ValueError as ve:
        if ctx:
            await ctx.error("Missing GITHUB_TOKEN")
        return _error_response("unauthorized", 401, str(ve))
    except GithubException as ge:
        status = getattr(ge, "status", 500) or 500
        msg = getattr(ge, "data", {}).get("message", str(ge)) if hasattr(ge, "data") else str(ge)
        # Common cases: 422 validation failed (e.g., branch protection, unknown head)
        if status in (409, 422):
            err_type = "conflict"
            status = 409
        elif status == 404:
            err_type = "not_found"
        elif status == 403:
            err_type = "forbidden"
        else:
            err_type = "github_api_error"
        if ctx:
            await ctx.error(f"GitHub API error: {msg}")
        return _error_response(err_type, status, msg)
    except Exception as e:
        if ctx:
            await ctx.error("Unexpected error during PR creation")
        return _error_response("internal_error", 500, str(e))


@mcp.resource("gh://{owner}/{repo}/readme")
async def gh_readme(owner: str, repo: str, ctx: Context) -> str:
    """Return repository README text (UTF-8)."""
    try:
        await ctx.info(f"Reading README for {owner}/{repo}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        readme = repository.get_readme()
        return readme.decoded_content.decode("utf-8", errors="replace")
    except Exception as e:
        # For resources, raise a simple error string; client can inspect logs
        await ctx.error(f"Failed to read README: {e}")
        return f"ERROR: {e}"


@mcp.resource("gh://{owner}/{repo}/file/{path}?ref={ref}")
async def gh_file_text(owner: str, repo: str, path: str, ref: str = "main", ctx: Context | None = None) -> str:
    """Return small text file content at ref (UTF-8)."""
    try:
        if ctx:
            await ctx.info(f"Reading text file {path} at {owner}/{repo}@{ref}")
        gh = _gh()
        repository = gh.get_repo(f"{owner}/{repo}")
        content_file = repository.get_contents(path, ref=ref)
        return content_file.decoded_content.decode("utf-8", errors="replace")
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to read file resource: {e}")
        return f"ERROR: {e}"


@mcp.prompt(name="commit_message", description="변경 요약 bullet들을 커밋 메시지로 압축")
def commit_message(bullets: list[str] | str) -> list[Any]:
    """Return system/user messages for an LLM to craft a commit message.

    Args:
        bullets: List of bullet lines or a single string with newlines.
    Returns:
        A list of PromptMessage objects (system + user).
    """
    if isinstance(bullets, str):
        bullet_text = bullets.strip()
    else:
        bullet_text = "\n".join([b.strip("\n") for b in bullets])

    system_text = (
        "You are a helpful assistant that formats concise commit messages. "
        "Return an English 1-line title (<=72 chars) and a Korean body (3-5 lines)."
    )
    user_text = (
        "Summarize these change bullets into a conventional commits style message.\n\n"
        f"Bullets:\n{bullet_text}\n\n"
        "Format:\n"
        "<title: English, one line>\n\n"
        "- <한국어 본문 3~5줄, 항목은 대시로 시작>\n"
        "- <왜/무엇이 변경되었는지 중심>\n"
        "- <리스크/브레이킹체인지가 있다면 표기>\n"
    )

    return [
        Message.system(system_text),
        Message.user(user_text),
    ]


if __name__ == "__main__":
    # Streamable HTTP server
    mcp.run(transport="http", host="127.0.0.1", port=8765, path="/mcp")