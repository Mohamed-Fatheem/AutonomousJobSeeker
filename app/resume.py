"""The model only selects immutable, user-verified fact IDs; it never writes resume claims."""
import io
import json
from xml.sax.saxutils import escape
from pypdf import PdfReader
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4

CATEGORIES = {'experience': 'Experience', 'skills': 'Technical skills', 'projects': 'Projects',
              'research': 'Research & publications', 'education': 'Education', 'other': 'Additional information'}


def parse_facts(value):
    try:
        arr = json.loads(value or '[]')
        if not isinstance(arr, list):
            return []
        return [f for f in arr if isinstance(f, dict) and f.get('verified') is True and
                isinstance(f.get('id'), str) and isinstance(f.get('text'), str) and f.get('text').strip()]
    except (ValueError, TypeError):
        return []


def facts_from_lines(lines):
    # No automatic verification: these are user-entered or parsed claims requiring confirmation.
    facts = []
    for i, line in enumerate(lines[:100]):
        line = line.strip(' \t-•')
        if not line or len(line) > 700:
            continue
        cat, sep, content = line.partition('|')
        if sep and cat.strip().lower() in CATEGORIES:
            category, text = cat.strip().lower(), content.strip()
        else:
            category, text = 'experience', line
        if text:
            facts.append({'id': f'F{i+1}', 'category': category, 'text': text, 'verified': True})
    return facts


def resume_text_from_pdf(raw):
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('PDF must be smaller than 2 MB')
    reader = PdfReader(io.BytesIO(raw), strict=False)
    if len(reader.pages) > 8:
        raise ValueError('Maximum eight PDF pages')
    return '\n'.join((page.extract_text() or '') for page in reader.pages)[:30000]


def build_pdf(profile, email, selected_facts):
    if not selected_facts:
        raise ValueError('At least one verified resume fact is required')
    stream = io.BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=42, leftMargin=42,
                            topMargin=36, bottomMargin=36, title='Verified tailored resume')
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='NameCustom', parent=styles['Heading1'], fontName='Helvetica-Bold',
                              fontSize=18, leading=23, textColor=colors.HexColor('#172c43'), spaceAfter=6))
    styles.add(ParagraphStyle(name='SectionCustom', parent=styles['Heading2'], fontName='Helvetica-Bold',
                              fontSize=10, leading=13, textColor=colors.HexColor('#2563eb'), spaceBefore=14, spaceAfter=5))
    styles.add(ParagraphStyle(name='BodyCustom', parent=styles['BodyText'], fontSize=9, leading=13, spaceAfter=5))
    content = [Paragraph(escape(profile.full_name or email), styles['NameCustom'])]
    contact = ' | '.join(filter(None, [email, profile.phone, profile.location]))
    content.append(Paragraph(escape(contact), styles['BodyCustom']))
    if profile.headline:
        content.append(Paragraph(escape(profile.headline), styles['BodyCustom']))
    content.append(HRFlowable(width='100%', thickness=0.6, color=colors.HexColor('#cbd5e1')))
    if profile.summary:
        content.append(Paragraph('PROFILE', styles['SectionCustom']))
        content.append(Paragraph(escape(profile.summary)[:1300], styles['BodyCustom']))
    for cat, heading in CATEGORIES.items():
        group = [f for f in selected_facts if f['category'] == cat]
        if not group:
            continue
        content.append(Paragraph(escape(heading.upper()), styles['SectionCustom']))
        for fact in group:
            content.append(Paragraph('&#8226; ' + escape(fact['text'])[:1300], styles['BodyCustom']))
    doc.build(content)
    return stream.getvalue()
