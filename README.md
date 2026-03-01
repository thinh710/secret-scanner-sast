# Secret Scanner (Secrets + SAST Regex)

Tool Python CLI để quét:
- **Secrets** (AWS/GitHub/Slack/private key/connection string, v.v.)
- **SAST dạng regex (heuristic)**: một số pattern rủi ro như SQLi concat, command injection, hardcoded password, insecure upload (PHP).

> Lưu ý: SAST regex chỉ là heuristic (có thể false positive/false negative). Muốn mạnh hơn, nên dùng thêm Semgrep/CodeQL.

## Cài đặt

```bash
pip install -r requirements.txt
```
<img width="1017" height="554" alt="image" src="https://github.com/user-attachments/assets/ad39a8b1-3cb1-437f-8d29-0864530b0552" />


## Chạy

Quét và in ra console:
```bash
python cli.py .
```
<img width="1645" height="781" alt="image" src="https://github.com/user-attachments/assets/5f589992-5f42-4112-95ab-a344d02b478b" />


Xuất JSON/CSV/HTML:
```bash
python cli.py . -o report.json
python cli.py . -o report.csv
python cli.py . -o report.html
```
<img width="1573" height="335" alt="image" src="https://github.com/user-attachments/assets/abf9318c-a2fe-4092-928e-917f1a64f079" />
<img width="1874" height="921" alt="image" src="https://github.com/user-attachments/assets/31e94286-f498-4164-bbc1-98756a61a8c5" />


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
<img width="1557" height="826" alt="image" src="https://github.com/user-attachments/assets/78dff986-44fb-4e6e-b52d-be7ace2e104b" />


Options:
- Pick a folder to scan
- Choose output format (HTML/JSON/CSV)
- Export fix guidance file
- Toggle SAST and unmask values (for fake/test data)
