# app.py
import streamlit as st
import fitz  # pymupdf
import pandas as pd
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

st.set_page_config(page_title="PDF Link Proofing Agent", layout="wide")

# ---------- Utilities ----------
def normalize_url(u: str):
    if not u:
        return ""
    u = u.strip()
    # Remove trailing punctuation often captured by text regex
    return u.rstrip(').,;:\'"')

def extract_candidates(pdf_path: str):
    doc = fitz.open(pdf_path)
    candidates = []
    for pno in range(doc.page_count):
        page = doc[pno]
        # annotation links (hidden behind "CLICK HERE" etc.)
        for ln in page.get_links():
            rect = ln.get("from")
            if not rect:
                continue
            try:
                r = fitz.Rect(rect)
                bbox = [r.x0, r.y0, r.x1, r.y1]
            except Exception:
                # fallback if already a tuple
                bbox = list(rect)
            target = ln.get("uri") or ln.get("dest") or ""
            candidates.append({
                "source": "annotation",
                "page": pno + 1,
                "bbox": bbox,
                "target": normalize_url(str(target)),
                "kind": ln.get("kind")
            })
        # text-based URLs (visible in text)
        text = page.get_text("text")
        if text:
            for m in re.findall(r'https?://[^\s\)\]\}\>,;"]+', text):
                candidates.append({
                    "source": "text",
                    "page": pno + 1,
                    "bbox": "",
                    "target": normalize_url(m),
                    "kind": "text"
                })
    # dedupe (keep first occurrence)
    seen = set()
    unique = []
    for c in candidates:
        key = (c["target"], c["page"])
        if key[0] and key not in seen:
            seen.add(key)
            unique.append(c)
    return unique

def check_url_simple(url, timeout=10):
    # classify non-http schemes quickly
    if not url:
        return {"status": "empty", "code": None, "final_url": None, "error": None}
    if url.startswith("mailto:"):
        return {"status": "mailto", "code": None, "final_url": None, "error": None}
    if url.startswith("tel:"):
        return {"status": "tel", "code": None, "final_url": None, "error": None}
    if url.startswith("pdf:") or url.startswith("goto:") or url.startswith("('"):
        return {"status": "internal_pdf", "code": None, "final_url": None, "error": None}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"status": "other_scheme", "code": None, "final_url": None, "error": None}

    try:
        # Try HEAD first (faster), fallback to GET for 405 or other issues
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        code = resp.status_code
        final = resp.url
        if code == 405 or code >= 400:
            resp = requests.get(url, allow_redirects=True, timeout=timeout)
            code = resp.status_code
            final = resp.url
        status = "ok" if code < 400 else "broken"
        return {"status": status, "code": code, "final_url": final, "error": None}
    except requests.exceptions.SSLError as e:
        return {"status": "tls_error", "code": None, "final_url": None, "error": str(e)}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "code": None, "final_url": None, "error": str(e)}

# ---------- Streamlit UI ----------
st.title("PDF Link Proofing Agent — MVP")
st.markdown("Upload a PDF. This tool extracts hidden link annotations and visible text URLs, then does a simple HTTP check.")

uploaded = st.file_uploader("Upload PDF", type=["pdf"])

if uploaded:
    temp_path = "uploaded.pdf"
    with open(temp_path, "wb") as f:
        f.write(uploaded.read())
    st.success("PDF uploaded. Extracting link candidates...")
    with st.spinner("Extracting..."):
        candidates = extract_candidates(temp_path)

    if not candidates:
        st.info("No link annotations or text URLs found in this PDF.")
    else:
        st.write(f"Found **{len(candidates)}** candidates (annotations + text URLs).")
        df_candidates = pd.DataFrame(candidates)
        st.dataframe(df_candidates[["page","source","target","kind"]], height=300)

        if st.button("Run link validation (simple HTTP checks)"):
            st.info("Validating links — this may take a little while depending on how many links there are.")
            results = []
            progress = st.progress(0)
            total = len(candidates)
            i = 0
            # Use a ThreadPool for parallel checks
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = {ex.submit(check_url_simple, c["target"]): c for c in candidates}
                for fut in as_completed(futures):
                    c = futures[fut]
                    res = fut.result()
                    results.append({
                        "page": c["page"],
                        "source": c["source"],
                        "target": c["target"],
                        "kind": c["kind"],
                        "status": res["status"],
                        "http_code": res.get("code"),
                        "final_url": res.get("final_url"),
                        "error": res.get("error"),
                        "bbox": c["bbox"]
                    })
                    i += 1
                    progress.progress(int(i / total * 100))
            df = pd.DataFrame(results)
            st.success("Validation complete.")
            st.dataframe(df, height=400)

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV report", csv, file_name="pdf_link_report.csv", mime="text/csv")
