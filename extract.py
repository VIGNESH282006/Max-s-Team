import PyPDF2

def main():
    try:
        with open(r'd:\Hackathon\cyber_threat_detection (1).pdf', 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            text = '\n'.join([page.extract_text() for page in reader.pages if page.extract_text()])
        with open('pdf_content.txt', 'w', encoding='utf-8') as f:
            f.write(text)
        print("Successfully extracted PDF text")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
