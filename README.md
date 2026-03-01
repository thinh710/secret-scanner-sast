# Secret Scanner (Secrets + SAST Regex)

Tool Python CLI để quét:
- **Secrets** (AWS/GitHub/Slack/private key/connection string, v.v.)
- **SAST dạng regex (heuristic)**: một số pattern rủi ro như SQLi concat, command injection, hardcoded password, insecure upload (PHP).

> Lưu ý: SAST regex chỉ là heuristic (có thể false positive/false negative). Muốn mạnh hơn, nên dùng thêm Semgrep/CodeQL.

## Cài đặt

```bash
pip install -r requirements.txt
```

## Chạy

Quét và in ra console:
```bash
python cli.py .
```

Xuất JSON/CSV/HTML:
```bash
python cli.py . -o report.json
python cli.py . -o report.csv
python cli.py . -o report.html
```

Tắt SAST (chỉ quét secrets):
```bash
python cli.py . --no-sast -o secrets.json
```

Chỉ lấy từ mức severity trở lên:
```bash
python cli.py . --severity-threshold High -o report.html
```

Giới hạn dung lượng file (để tránh scan file quá lớn):
```bash
python cli.py . --max-file-size-mb 5 -o report.json
```

## Cấu hình rules

Sửa `config/rules.json`:
- `type`: `secret` hoặc `sast`
- `pattern`: regex
- `severity`: `Critical/High/Medium/Low`
- `remediation`: gợi ý fix
- (tùy chọn) `capture_group`, `min_length`, `entropy_threshold`, `keywords`, `proximity_window`


## GUI (no CLI)
Run on Windows (Tkinter is built-in):

```bat
run_gui.bat
```

Options:
- Pick a folder to scan
- Choose output format (HTML/JSON/CSV)
- Export fix guidance file
- Toggle SAST and unmask values (for fake/test data)
