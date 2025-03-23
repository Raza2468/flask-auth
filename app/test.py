import pdfplumber
import pandas as pd

# Path to the uploaded PDF file
pdf_path = "/mnt/data/DXC-PayerList.pdf"

data = []
with pdfplumber.open(pdf_path) as pdf:
    for page in pdf.pages:
        tables = page.extract_tables()
        for table in tables:
            for row in table:
                # Skip headers and empty rows
                if any("Payer ID" in str(cell) for cell in row) or not any(row):
                    continue
                data.append(row)

# Convert extracted data to a DataFrame
df = pd.DataFrame(data, columns=["Payer ID", "Name", "CLM", "ELI", "BEN", "STA", "ERA", "RTC", "ATT"])

# Clean the DataFrame: Drop any fully empty columns, strip spaces, and remove unwanted characters
df = df.dropna(how='all')  # Drop fully empty rows
df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)  # Strip spaces

# Save as CSV
csv_path = "/mnt/data/DXC-PayerList.csv"
df.to_csv(csv_path, index=False)

# Display CSV file for download
import ace_tools as tools
tools.display_dataframe_to_user(name="Payer List", dataframe=df)

csv_path
