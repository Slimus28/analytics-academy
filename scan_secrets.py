#!/usr/bin/env python3
"""Проверка перед коммитом: нет ли в файлах паролей и строк подключения.

Запускать из корня репозитория:  python scan_secrets.py
Выход 1 означает, что коммитить нельзя.
"""
import json, re, sys, pathlib

# Шаблоны вида postgresql://%s:%s@... или {DB_PASS} — это НЕ утечка:
# пароль подставляется на лету. Поэтому строки с %, { и $ в месте
# логина-пароля пропускаются, иначе проверка кричит на нормальный код.
_NOT_TPL = r'(?![^:\s]*[%{$])'
PATTERNS = [
    (r'postgresql(\+\w+)?://' + _NOT_TPL + r'[^:\s]+:(?![^@\s]*[%{$])[^@\s]+@',
     'строка подключения с паролем'),
    (r'(?i)\b(password|passwd|pwd|db_pass)\s*=\s*[\'"](?![%{$])[^\'"]{3,}[\'"]', 'пароль в коде'),
    (r'(?i)\bapi[_-]?key\s*=\s*[\'"][^\'"]{8,}[\'"]', 'API-ключ'),
    (r'\bAKIA[0-9A-Z]{16}\b', 'ключ AWS'),
    (r'(?i)\bsk-[A-Za-z0-9]{20,}', 'токен вида sk-...'),
]
# Явные заглушки в примерах и README — не секреты
PLACEHOLDER = re.compile(
    r'(?i)ваш[_ -]?пароль|your[_ -]?password|password_here|<[^>]+>|xxx+|\.\.\.')

SKIP_DIRS = {'.git', '.venv', 'venv', '__pycache__', '.ipynb_checkpoints', 'node_modules'}

def texts(path):
    """Вернуть куски текста файла: для ноутбука — код ячеек И их выводы."""
    if path.suffix == '.ipynb':
        try:
            nb = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return
        for n, cell in enumerate(nb.get('cells', []), 1):
            yield 'ячейка %d, код' % n, ''.join(cell.get('source', []))
            for out in cell.get('outputs', []):
                for key in ('text',):
                    if key in out:
                        yield 'ячейка %d, вывод' % n, ''.join(out[key])
                data = out.get('data', {})
                if 'text/plain' in data:
                    yield 'ячейка %d, вывод' % n, ''.join(data['text/plain'])
    else:
        yield '', path.read_text(encoding='utf-8', errors='ignore')

def main():
    root = pathlib.Path('.')
    hits = []
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in {'.ipynb', '.py', '.md', '.txt', '.yml', '.yaml', '.json', '.sql', '.sh'}:
            continue
        if path.name == 'scan_secrets.py':
            continue
        for where, chunk in texts(path):
            for pat, label in PATTERNS:
                for m in re.finditer(pat, chunk):
                    if PLACEHOLDER.search(m.group(0)):
                        continue        # это пример в документации, не секрет
                    line = chunk[:m.start()].count('\n') + 1
                    hits.append((str(path), where or ('строка %d' % line), label,
                                 m.group(0)[:60]))

    if hits:
        print('НАЙДЕНЫ СЕКРЕТЫ — коммитить нельзя:\n')
        for f, where, label, frag in hits:
            print('  %s | %s | %s\n    %s...\n' % (f, where, label, frag))
        print('Уберите их и запустите проверку заново.')
        return 1

    print('Секретов не найдено. Можно коммитить.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
