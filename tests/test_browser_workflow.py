"""Real-browser regression for the data-loss workflow. Uses isolated test DB."""
import io
import os
import socket
import threading
import time
from pathlib import Path
import pytest
import uvicorn
from reportlab.pdfgen import canvas
from app.main import app


def test_drafts_save_states_upload_and_mobile_layout():
    playwright = pytest.importorskip('playwright.sync_api')
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='error'))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(.05)
    try:
        with playwright.sync_playwright() as pw:
            browser = pw.chromium.launch(channel='msedge' if os.name == 'nt' else 'chromium', headless=True)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{port}/register')
            page.locator('[name=email]').fill('browser@example.com')
            page.locator('[name=password]').fill('long-safe-password-for-testing')
            page.locator('[name=invite]').fill('test-invite-protected')
            page.locator('form[action="/register"] button').click()
            page.wait_for_url('**/profile')
            save = page.locator('form[action="/profile"] button')
            assert save.is_disabled()
            page.locator('[name=full_name]').fill('Draft Candidate')
            page.locator('[name=fact_lines]').fill('skills | Python and SQL')
            assert save.is_enabled()
            page.reload()
            assert page.locator('[name=full_name]').input_value() == 'Draft Candidate'
            raw = io.BytesIO()
            pdf = canvas.Canvas(raw)
            pdf.drawString(50, 700, 'Existing resume for reference')
            pdf.save()
            page.locator('input[type=file]').set_input_files({'name':'resume.pdf', 'mimeType':'application/pdf', 'buffer':raw.getvalue()})
            page.locator('form[action="/profile/upload"] button').click()
            page.wait_for_load_state('networkidle')
            assert page.locator('[name=full_name]').input_value() == 'Draft Candidate'
            assert page.locator('[name=fact_lines]').input_value() == 'skills | Python and SQL'
            save.click()
            page.wait_for_load_state('networkidle')
            assert save.is_disabled()
            page.reload()
            assert page.locator('[name=full_name]').input_value() == 'Draft Candidate'
            assert save.is_disabled()
            for path in ('/settings', '/sources', '/', '/jobs/new', '/profile'):
                page.goto(f'http://127.0.0.1:{port}{path}')
                for width in (1440, 390):
                    page.set_viewport_size({'width':width, 'height':900})
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), path
                    if path in ('/settings', '/profile'):
                        output = Path(__file__).parent.parent / 'test_artifacts'
                        output.mkdir(exist_ok=True)
                        page.screenshot(path=str(output / f'{path.strip("/")}-{width}.png'), full_page=True)
            page.goto(f'http://127.0.0.1:{port}/settings')
            page.locator('[name=daily_limit]').fill('7')
            page.reload()
            assert page.locator('[name=daily_limit]').input_value() == '7'
            page.goto(f'http://127.0.0.1:{port}/sources')
            page.locator('[name=platforms][value=linkedin]').uncheck()
            page.reload()
            assert not page.locator('[name=platforms][value=linkedin]').is_checked()
            assert not errors
            assert page.locator('link[rel=icon]').count() == 1
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
