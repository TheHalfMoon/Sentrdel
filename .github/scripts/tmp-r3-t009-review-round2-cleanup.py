from pathlib import Path

route = Path("crates/sentrdel-review/src/business_logic/route.rs")
text = route.read_text(encoding="utf-8")
old = '''    let route_pattern = format!("/functions/v1/{function_name}");
    let bytes = source.as_bytes();
    let mut index = 0;
'''
new = '''    let route_pattern = format!("/functions/v1/{function_name}");
    let mut index = 0;
'''
assert text.count(old) == 1, text.count(old)
route.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
