from pathlib import Path
import shutil
import markdown
import re

PROJECT=Path(__file__).resolve().parent.parent
ROOT=PROJECT/'.preview'
ROOT.mkdir(exist_ok=True)
brand=ROOT/'assets'/'brand'
if brand.exists():
    shutil.rmtree(brand)
shutil.copytree(PROJECT/'assets'/'brand',brand)
for filename in ('LICENSE','NOTICE'):
    shutil.copyfile(PROJECT/filename,ROOT/filename)
css='''*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body.light{background:#fff;color:#1f2328}.repo{max-width:1070px;margin:0 auto;padding:25px 26px 50px}.file{font:12px/1.4 ui-monospace,monospace;color:#8c959f;margin:0 0 17px}.readme{padding:32px;border:1px solid #30363d;border-radius:7px}.light .readme{border-color:#d1d9e0}img{max-width:100%;height:auto;display:block}.readme h1{font-size:32px;line-height:1.25;letter-spacing:-.7px;margin:28px 0 15px;padding-bottom:9px;border-bottom:1px solid #30363d}.readme h2{font-size:24px;line-height:1.4;margin:28px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d}.light .readme h1,.light .readme h2{border-color:#d1d9e0}.readme p{margin:0 0 16px}.readme ul{padding-left:24px;margin-bottom:24px}.readme li{margin:8px 0}.readme blockquote{margin:16px 0 24px;padding-left:16px;border-left:4px solid #3d444d;color:#9198a1}.readme blockquote p{margin:0}.light .readme blockquote{border-color:#d1d9e0;color:#59636e}a{color:#79c0ff;text-underline-offset:3px}.light a{color:#0969da}.toolbar{display:flex;flex-wrap:wrap;gap:15px;align-items:center;background:#1b1d22;border-bottom:1px solid #3b3e45;padding:13px 24px;color:#eef0f3;font-size:13px}.toolbar strong{margin-right:auto}.toolbar button{background:transparent;border:1px solid #54565d;color:inherit;padding:10px 14px;cursor:pointer;border-radius:5px}.toolbar a{color:inherit}a:focus-visible,button:focus-visible{outline:3px solid #2cccc3;outline-offset:4px}@media(max-width:600px){.repo{padding:16px 10px 36px}.readme{padding:16px}.readme h1{font-size:27px}.readme h2{font-size:22px}.toolbar{padding:12px}.toolbar strong{width:100%}}'''
body=markdown.markdown((PROJECT/'README.md').read_text(),extensions=['tables','fenced_code'])
body=re.sub(r'href="([^"]+)\.md"', r'href="\1.html"', body)
page='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentSwapper | Final README</title><style>'''+css+'''</style><body><div class="toolbar"><strong>AgentSwapper / selected Distinction design</strong><a href="index.html">Design gallery</a><button id="mode">Switch reading mode</button></div><main class="repo"><p class="file">agentswapper / README.md</p><article class="readme">'''+body+'''</article></main><script>let mode=new URLSearchParams(location.search).get('mode')||'dark';function render(){document.body.classList.toggle('light',mode==='light');document.querySelectorAll('picture source').forEach(s=>s.media=mode==='dark'?'all':'not all')}document.getElementById('mode').onclick=()=>{mode=mode==='dark'?'light':'dark';render()};render();</script></body></html>'''
(ROOT/'final.html').write_text(page)
(ROOT/'docs').mkdir(exist_ok=True)
for name in ('architecture','roadmap','cli','testing','support-matrix','handover','dependencies','registry'):
    content=markdown.markdown((PROJECT/'docs'/f'{name}.md').read_text(),extensions=['tables','fenced_code'])
    content=re.sub(r'href="([^"]+)\.md"', r'href="\1.html"', content)
    (ROOT/'docs'/f'{name}.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentSwapper '+name+'</title><style>body{max-width:1000px;margin:40px auto;padding:0 24px;font:16px/1.7 sans-serif;background:#fbfaf6;color:#242632}pre{padding:18px;background:#edeae5;overflow:auto}table{border-collapse:collapse;display:block;overflow:auto}td,th{border:1px solid #c7c5c4;padding:8px 12px}a{color:#2453a6}</style><a href="../final.html">Back to README</a>'+content+'</html>')
index=ROOT/'index.html'
text=index.read_text() if index.exists() else '<!doctype html><meta http-equiv="refresh" content="0;url=final.html">'
if 'View selected README' not in text:
    text=text.replace('<main class="gallery">','<p style="max-width:1440px;margin:0 auto 26px;padding:0 40px;font-size:17px"><a href="final.html" style="color:#155d61;font-weight:700;text-decoration:underline">View selected README: Distinction + custom relay artwork</a></p><main class="gallery">')
    index.write_text(text)
contributing=markdown.markdown((PROJECT/'CONTRIBUTING.md').read_text(),extensions=['tables','fenced_code'])
contributing=re.sub(r'href="([^"]+)\.md"', r'href="\1.html"', contributing)
(ROOT/'CONTRIBUTING.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentSwapper / Contributing</title><style>'+css+'</style><main class="repo"><a href="final.html">Back to README</a>'+contributing+'</main></html>')
print('Final README preview: http://localhost:4317/final.html')
