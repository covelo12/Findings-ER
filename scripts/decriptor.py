def xor_data(data, key):
    return bytes([byte ^ key for byte in data])

def find_string(data, string):
    index = data.find(string.encode())
    return index if index != -1 else None
    
def main():
    # Open the PDF file
    with open('guia_500_comandos_Linux.pdf', 'rb') as file:
        pdf_data = file.read()

    # XOR the PDF data with 0xf8
    xored_data = xor_data(pdf_data, 0xf8)

    # Write the bytes after 'run' to a file
    with open('extracted_bytes.bin', 'wb') as output_file:
        output_file.write(xored_data)
    
    print("Bytes after 'run' written to 'extracted_bytes.bin'")

if __name__ == "__main__":
    main()
