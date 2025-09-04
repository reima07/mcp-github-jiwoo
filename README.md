## github-mcp (fastmcp + PyGithub)

로컬에서 실행되는 Streamable HTTP 기반 MCP 서버입니다. GitHub 작업을 위한 기본 툴셋, 리소스, 프롬프트를 제공합니다.

### 의존성
- Python 3.11+
- fastmcp (최신)
- PyGithub (최신)
- python-dotenv (선택)

### 설치

uv 권장, pip도 가능.

```bash
cd mcp-github

# uv
uv venv -p 3.11
source .venv/bin/activate
uv pip install --upgrade fastmcp PyGithub python-dotenv

# 또는 pip
# python3.11 -m venv .venv && source .venv/bin/activate
# pip install --upgrade fastmcp PyGithub python-dotenv
```

### 환경변수
`GITHUB_TOKEN`이 필요합니다. 권장 스코프: `repo` (PR/브랜치/콘텐츠 조작 포함). 워크플로를 조작한다면 `workflow`도 추가하세요.

`.env` 사용 시 다음 예시를 참고하세요.

```bash
cp .env.example .env
# .env 열어서 GITHUB_TOKEN 세팅
```

### 실행

```bash
python server.py
# 127.0.0.1:8765 에서 HTTP MCP 엔드포인트가 /mcp 로 열립니다.
```

### Cursor 연결
워크스페이스 루트(`.cursor/mcp.json`)에 아래 설정을 추가합니다.

```json
{
  "mcpServers": {
    "github-mcp": {
      "url": "http://127.0.0.1:8765/mcp",
      "env": {
        "GITHUB_TOKEN": "★★여기에_퍼스널_액세스_토큰★★"
      }
    }
  }
}
```

Cursor를 재시작하거나 "Reload MCP"를 실행하면 서버가 등록됩니다.

### 제공 기능

- Tools
  - `gh_auth_check()` → { login, scopes, rate_limit }
  - `gh_list_repos(visibility="all", limit=30)` → { repos: [{ full_name, private }] }
  - `gh_create_repo(name, description=None, private=False, auto_init=True, gitignore_template=None, license_template=None)` → { full_name, html_url, clone_url, private }
  - `gh_list_branches(owner, repo)` → { branches }
  - `gh_create_branch(owner, repo, new_branch, from_ref="main")` → { ref, sha }
  - `gh_get_file(owner, repo, path, ref="main")` → { path, sha, encoding: "base64", content }
  - `gh_upsert_file(owner, repo, path, message, content, branch="main", content_encoding="plain"|"base64")` → { status, sha }
  - `gh_create_pr(owner, repo, base, head, title, body=None)` → { number, url }

- Resources
  - `gh://{owner}/{repo}/readme` → 리포지토리 README(UTF-8)
  - `gh://{owner}/{repo}/file/{path}?ref={ref}` → 특정 텍스트 파일(소용량)

- Prompt
  - name: `commit_message` (arguments: `bullets`)
    - system/user 메시지 형태로, 영어 1줄 제목 + 한국어 본문(3~5줄) 템플릿을 반환

### 예시 워크플로

1) 툴 목록 확인
   - Cursor 내 Tools 목록에서 `github-mcp`에 노출되는 툴들을 확인합니다.

2) 인증 확인
   - `gh_auth_check` 호출 → 현재 로그인/레이트리밋/스코프 확인

3) 레포지토리 생성
   - `gh_create_repo` (name, description, private=False, auto_init=True, gitignore_template="Python", license_template="mit")
   - 새 레포지토리 생성 시 자동으로 README, .gitignore, LICENSE 파일이 포함됩니다

4) 브랜치 → 파일 → PR 생성
   - `gh_create_branch` (owner, repo, new_branch, from_ref="main")
   - `gh_upsert_file` (owner, repo, path, message, content, branch=new_branch)
     - 바이너리/대용량 대비: `content_encoding="base64"`를 지원합니다
   - `gh_create_pr` (owner, repo, base="main", head=new_branch, title, body)

### 에러 처리
모든 툴은 실패 시 아래 형태로 일관된 에러 오브젝트를 반환합니다.

```json
{
  "error": {
    "type": "not_found|conflict|forbidden|unauthorized|github_api_error|internal_error",
    "status": 404,
    "message": "..."
  }
}
```

브랜치 보호 규칙/권한 부족/파일 충돌 등의 상황을 위 상태코드와 메시지로 돌려줍니다.

### 주의 사항
- 토큰은 절대 로그에 출력하지 않습니다.
- `gh_get_file`은 항상 base64 콘텐츠를 반환합니다(바이너리 호환).
- `gh_upsert_file`은 파일이 존재하면 update, 없으면 create를 수행하며, update 시 현재 SHA를 조회해 충돌을 방지합니다.