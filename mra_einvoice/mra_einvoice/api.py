import frappe
import base64
import json
import os, secrets
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from Crypto.Util.Padding import pad

import requests
from Crypto.Cipher import AES
import hashlib


def auth():

    einvoice_settings = frappe.get_doc("MRA eInvoice Settings")

    # Step 1
    encryption_key = os.urandom(32)
    aeskey = base64.b64encode(encryption_key).decode('utf-8')
    # Step 2
    payload_to_encrypt = {
        "username": einvoice_settings.user_name,
        "password": einvoice_settings.get_password("user_password"),
        "encryptKey": aeskey,
        "refreshToken": True
    }

    # Step 3
    json_payload = json.dumps(payload_to_encrypt)

    encrypted_base64 = encrypt_payload(json_payload, is_auth=True)

    # Step 5
    request_id = frappe.generate_hash(length=15)
    payload = {
        "requestId": request_id,
        "payload": encrypted_base64
    }

    headers= {
        "accept": "application/json",
        "Content-Type": "application/json",
        "username": einvoice_settings.user_name,
        "ebsMraId": einvoice_settings.ebs_mra_id,
        "areaCode": einvoice_settings.area_code
    }

    # Output the JSON
    # print(json.dumps(payload))

    auth = requests.request('POST', einvoice_settings.authentication_url, data=json.dumps(payload), headers=headers)

    payload_to_encrypt["password"] = "*****"
    auth_log = frappe.get_doc({
        "doctype": "MRA eInvoice Log",
        "request_id": request_id,
        "request_type": "AUTH",
        "request": {"payload": payload, "headers": headers},
        "response_status": auth.status_code,
        "response": auth.json(),
        "aes_key": aeskey,
        "mra_key": auth.json().get("key"),
        "mra_token": auth.json().get("token"),
        "payload": payload_to_encrypt
    }).insert()

    frappe.db.commit()

    if auth.status_code == 200:
        return auth_log

    frappe.throw(f"Authenctication Error Check <a href='/app/mra-einvoice-log/{auth_log.name}'>{auth_log.name}</a>")

def transmit(sales_invoice, mraKey, aeskey, token, prevNote):

    json_payload = json.dumps(sales_invoice)
    encrypted_base64 = encrypt_payload(json_payload, mraKey=mraKey, aeskey=aeskey, is_invoice=True)

    request_id = frappe.generate_hash(length=10)
    payload = {
        "requestId": request_id,
        "requestDateTime": str(frappe.utils.get_datetime())[0:19].replace("-",""),
        "encryptedInvoice": encrypted_base64
    }

    # print(json.dumps(payload))
    einvoice_settings = frappe.get_doc("MRA eInvoice Settings")

    headers= {
        "accept": "application/json",
        "Content-Type": "application/json",
        "ebsMraId": einvoice_settings.ebs_mra_id,
        "username": einvoice_settings.user_name,
        "areaCode": einvoice_settings.area_code,
        "token": token
    }

    # Output the JSON
    # print(json.dumps(payload))

    transmit = requests.request('POST', einvoice_settings.transmit_url, data=json.dumps(payload), headers=headers)

    auth_log = frappe.get_doc({
        "doctype": "MRA eInvoice Log",
        "request_id": request_id,
        "request_type": "TRANSMIT",
        "request": {"payload": payload, "headers": headers},
        "response_status": transmit.status_code,
        "response": transmit.json(),
        "aes_key": aeskey,
        "mra_key": transmit.json().get("key"),
        "mra_token": transmit.json().get("token"),
        "payload": sales_invoice[0]
    }).insert()

    frappe.db.commit()

    if transmit.status_code == 200:
        errors = []
        if transmit.json().get("status") =="ERROR":
            for inv in transmit.json().get("fiscalisedInvoices"):
                for error in  inv.get("errorMessages"):
                    errors.append(f'{error.get("code")} - {error.get("description")}')
            frappe.response["message"] = {"status": False, "messages": errors}

        if transmit.json().get("status") =="SUCCESS":
            for inv in transmit.json().get("fiscalisedInvoices"):
                si = frappe.get_doc("Sales Invoice", inv.get("invoiceIdentifier"))
                si.mra_irn = inv.get("irn")
                si.mra_qr_code = inv.get("qrCode")
                si.mra_previous_invoice_hash = prevNote

                si.save()
                si.submit()

            frappe.response["message"] = {"status": True, "messages": f'e Invoice Generated Successfully. IRN : {inv.get("irn")}'}

    # frappe.response["message"] = auth_log.name
    # frappe.throw(f"Transmission Error Check <a href='/app/mra-einvoice-log/{auth_log.name}'>{auth_log.name}</a>")

def encrypt_payload(json_payload, mraKey=None, aeskey=None, is_auth=None, is_invoice=None):

    certificate_pem = b"""
    -----BEGIN CERTIFICATE-----
    MIIHyDCCBrCgAwIBAgIQB9ygjZ+YdqS7ERdjcLWwwTANBgkqhkiG9w0BAQ0FADBZ
    MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
    aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjMw
    NTIyMDAwMDAwWhcNMjQwMzEyMjM1OTU5WjBfMQswCQYDVQQGEwJNVTETMBEGA1UE
    BxMKUG9ydCBMb3VpczEkMCIGA1UEChMbTWF1cml0aXVzIFJldmVudWUgQXV0aG9y
    aXR5MRUwEwYDVQQDEwx2ZmlzYy5tcmEubXUwggIiMA0GCSqGSIb3DQEBAQUAA4IC
    DwAwggIKAoICAQCarsTAIeMek52K8SCbH2jD84fmIXjSHohXZU/GSgVfEBnwk2Wv
    ZXeJfkRMSWU4vdDJlsTDi0luDg5oArCWrZldiVpfpegXDj+daNVzj4d3QP/HgI02
    Q/+7yKRIV42orUXbyVDXqqukLW/JvGpzwHD4D4KbnV/3hjMxeMiQo7Yb08T+kytK
    cPdZWKyu85MXwaA/dBtkpkaXunYMRYqewLdJBbFK7QcI/mQ+1jxCS+F4IMSqGj+0
    Qct9V3MgXKEzh9iATDfXxejHrF5J59etSleRZBkIat2NPQ5n07miTpgVq1z33H8s
    jc44CXbJCemM1IzZD/IwiB2WNZaG2NaqSoQrUHrlIcrDRcz++nrtVvjLsrh1NZ8f
    IGvd+DkLrQ4HexI/k+rpSu2sh7C6AD1XkbhQwKD9rchNIgXQXuOVrQC4XpPHzjiq
    HRIAebSbnzdANV7NsnaTt1hslzLF995yi3RKcVoSiULUPJxWQLxO5evx9GpsoYc3
    zk9Hfdupa7m+i786Riqn5cLoYfr6XbPTKDZuQwavsiN+5h/7YR5KwFoeGzSWB00d
    BBSKoU4Cu2VWmjhaSritCKUcOP5T65PkKOsAFbz2CkqYWS8mSWksEKOi6YOwFkV1
    oqwI8sTbL5Cgdaxd1szqQcwgup2xfOx737Fi4JXdi/DXC3DyNqbmUJXO0wIDAQAB
    o4IDhDCCA4AwHwYDVR0jBBgwFoAUdIWAwGbH3zfez70pN6oDHb7tzRcwHQYDVR0O
    BBYEFF6twzXWvLU6IDuYN5KJP8/tQbXnMBcGA1UdEQQQMA6CDHZmaXNjLm1yYS5t
    dTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
    MIGfBgNVHR8EgZcwgZQwSKBGoESGQmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
    aWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNybDBIoEagRIZC
    aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsRzJUTFNSU0FT
    SEEyNTYyMDIwQ0ExLTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQICMCkwJwYIKwYB
    BQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBhwYIKwYBBQUHAQEE
    ezB5MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUQYIKwYB
    BQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2Jh
    bEcyVExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAJBgNVHRMEAjAAMIIBfQYKKwYB
    BAHWeQIEAgSCAW0EggFpAWcAdQDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlG
    cR+1mwAAAYhCAvCvAAAEAwBGMEQCICRU4lR6J5qIihmYlqnDTMX9P9NC++Vymyyl
    To1Yg0XZAiBvZRwal2xqbjfy7fq1i/ZDCAWmkXU1J6AkeFOBJk9AZgB3AEiw42va
    pkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABiEIC8K8AAAQDAEgwRgIhAMIC
    QR/sNMV9fCWzCZavY160XjNjRl7vaH2e+Mupb30lAiEA4zjUoYssOJN85Tcq4D/Q
    C88JZ6Ka8XFAaKbQpA1REncAdQDatr9rP7W2Ip+bwrtca+hwkXFsu1GEhTS9pD0w
    SNf7qwAAAYhCAvB5AAAEAwBGMEQCIACPzUMLqQTkyf1+++GJhu8FmErQCql32vVM
    ZTogAA/sAiAWuNAX4ruLNMhhen2oqR6ICQyvUbnLrrvSLA2bilw2jTANBgkqhkiG
    9w0BAQ0FAAOCAQEAG+S2fY7QCVv1GzLLZ3JCryzY10MOsY4h1hubVgvHUX5IaWX5
    qjqX+yBwWdeXg3vSDb+HnBY3b3SRb7Grl1Vy/N3DQ0zyD2pzL3w78JO7VjJVTkH7
    aJmpryXHWMjx+2whZ/K4jOvXhOlFyeXMtDFAcpNXZNcdQ1hfivVf3/i8cU1tsB1O
    m/ZcfoawE7DeSOW+0Tzvq0PzFft2t60apn1F7MrSSwpJVDAHJLwQS6N7SFs3M+lN
    LpGGylpxiVHrFW446pxpRgglqvbmxAyE0/mMJWl36KUez1ni7z+EoDQfz1eXWI0d
    8zhtempJV+oZc/KF7it56vcaSHnSn3wucXQxuw==
    -----END CERTIFICATE-----
    """

    if is_auth:

        certificate = x509.load_pem_x509_certificate(certificate_pem, default_backend())
        public_key = certificate.public_key()

        # Encrypt the payload
        encrypted = public_key.encrypt(
            json_payload.encode('utf-8'),
            asym_padding.PKCS1v15()
        )

        # Step 4
        encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')

    if is_invoice:


        frappe.log_error("keys", {"aeskey": aeskey, "mraKey": mraKey})

        # mraKey = 'Pj2OevBn6Sp/+PIX1PwXcVhY716sw117rcEbuV5fEFUMW0NcaX3gJ0u5kLrB4GKT'
        # aeskey = 'EpeD3qfiL9q+jZfHeJkcr5zk4TT0HsQqu76LRua9qYk='
        mraKey_decrypted = decrypt_mrakey(mraKey, aeskey)

        print(mraKey_decrypted.decode('utf-8'))

        encrypted_data = encrypt_invoice_data(json_payload, mraKey_decrypted)
        encrypted_base64 = base64.b64encode(encrypted_data).decode()
        print(encrypted_base64)

        # aeskey_decoded = base64.b64decode(aeskey)
        
        # cipher = AES.new(aeskey_decoded, AES.MODE_ECB)
        # decrypted_key = cipher.decrypt(mraKey)
        # hashed_key = hashlib.sha256(decrypted_key).digest()
        # # decrypted_key_str = decrypted_key.strip()


        # cipher = Cipher(algorithms.AES(hashed_key), modes.ECB(), backend=default_backend())
        # encryptor = cipher.encryptor()

        # padder = sym_padding.PKCS7(128).padder()
        # padded_data = padder.update(json_payload.encode()) + padder.finalize()

        # encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()

        # encrypted_base64 = base64.b64encode(encrypted_payload).decode('utf-8')

    return encrypted_base64

def decrypt_mrakey(mraKey, aeskey):
    # Decode the base64 encoded key
    aeskey_decoded = base64.b64decode(aeskey)
    
    # Create AES cipher in ECB mode
    cipher = AES.new(aeskey_decoded, AES.MODE_ECB)
    
    # Decrypt the mraKey
    decrypted_key = cipher.decrypt(base64.b64decode(mraKey))
    
    return decrypted_key

def encrypt_invoice_data(invoice_data, decrypted_key):
    # Decode the base64 encoded key
    decrypted_key_decoded = base64.b64decode(decrypted_key)
    
    # Create AES cipher in ECB mode
    cipher = AES.new(decrypted_key_decoded, AES.MODE_ECB)
    
    # Pad the invoice data to make it compatible with AES block size
    padded_data = pad(invoice_data.encode('utf-8'), AES.block_size)
    
    # Encrypt the invoice data
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data


@frappe.whitelist()
def generate_einvoice(d):
    doc = json.loads(d)

    customer = frappe.get_doc("Customer", doc.get("customer"))
    company = frappe.get_doc("Company", doc.get("company"))
    validate_einvoice(doc, customer, company)

    invoice_type = "STD"

    if doc.get("is_return") == 1:
        invoice_type = "CRN"

    if doc.get("is_debit_note") == 1:
        invoice_type = "DRN"

    if doc.get("is_training_invoice") == 1:
        invoice_type = "TRN"

    
    prevNote = "0"
    previous_invoice = frappe.get_last_doc("Sales Invoice", filters={"docstatus": 1, "mra_irn": ["is", "set"], "posting_date": [">", company.einvoice_applicable_from]})

    if previous_invoice:
        prevNote = f"{doc.get('posting_date').replace('-', '')} {frappe.utils.format_time(doc.get('posting_time'), 'HH:mm:ss')}{previous_invoice.grand_total}{company.brn}{previous_invoice.name}"
        prevNote_sha256 = hashlib.sha256()
        prevNote_sha256.update(prevNote.encode('utf-8'))
        prevNote = prevNote_sha256.hexdigest()


    einvoice= [{
        "invoiceCounter": str(frappe.db.count("Sales Invoice", filters={"docstatus": 1, "posting_date": [">=", company.einvoice_applicable_from]})),
        "transactionType": customer.type_of_transaction,
        "personType": frappe.db.get_value("Tax Category", customer.tax_category, "mra_code"),
        "invoiceTypeDesc": invoice_type,
        "currency": doc.get("currency"),
        "invoiceIdentifier": doc.get("name"),
        "invoiceRefIdentifier": doc.get("return_against") or "",
        "previousNoteHash": prevNote,
        "totalVatAmount": str(doc.get("total_taxes_and_charges")) or "",
        "totalAmtWoVatCur": str(doc.get("total")),
        "totalAmtWoVatMur": str(doc.get("base_total") if doc.get("currency") != 'MUR' else ""),
        "totalAmtPaid": str(doc.get("grand_total")),
        "invoiceTotal": str(doc.get("grand_total")),
        # "discountTotalAmount": "",
        "dateTimeInvoiceIssued": f"{doc.get('posting_date').replace('-', '')} {frappe.utils.format_time(doc.get('posting_time'), 'HH:mm:ss')}",
        "salesTransactions": "CREDIT",
        "seller": {
            "name": company.legal_name or "",
            "tradeName": company.name,
            "tan": company.tax_id or "",
            "brn": company.brn or "",
            "businessAddr": frappe.db.get_value("Address", doc.get("company_address"), "address_line1") or "",
        },
        "buyer": {
            "name": doc.get("customer_name") or "",
            "tan": customer.tax_id or "",
            "brn": customer.brn or "",
            "businessAddr": frappe.db.get_value("Address", doc.get("customer_address"), "address_line1") or "",
            "buyerType": frappe.db.get_value("Tax Category", customer.tax_category, "mra_code") or "",
        },
        
    }]

    einvoice[0]["itemList"] = []

    for i in doc.get("items"):
        nature_of_goods, mra_product_code = frappe.db.get_value("Item", i.get("item_code"), ["is_stock_item", "mra_product_code"])

        item_tax_rate = ""

        if i.get("item_tax_rate"):
            item_tax_rate = json.loads(i.get("item_tax_rate"))
            item_tax_rate = list(item_tax_rate.values())[0] if list(item_tax_rate.values()) else 0

        tax_code = "TC01" if item_tax_rate == 15 else "TC02"

        einvoice[0]["itemList"].append({
            "itemNo": str(i.get("idx")),
            "taxCode": tax_code,
            "nature": "GOODS" if nature_of_goods ==1 else "SERVICES",
            "currency": doc.get("currency"),
            "productCodeMra": mra_product_code,
            "productCodeOwn": i.get("item_code"),
            "itemDesc": i.get("item_name"),
            "quantity": str(i.get("qty") if nature_of_goods ==1 else ""),
            "unitPrice": str(i.get("price_list_rate") if nature_of_goods ==1 else ""),
            "discount": str(i.get("discount_amount")),
            "discountedValue": str(i.get("rate")),
            "amtWoVatCur": str(i.get("amount")),
            "amtWoVatMur": str(i.get("base_amount") if doc.get("currency") != 'MUR' else ""),
            "vatAmt": str((i.get("amount") * item_tax_rate) / 100),
            "totalPrice": str(i.get("amount") + ((i.get("amount") * item_tax_rate) / 100))
        })
    
    auth_log = auth()

    transmit(einvoice, auth_log.mra_key, auth_log.aes_key, auth_log.mra_token, prevNote)


def validate_einvoice(doc, customer, company):

    is_einvoice_applicable, einvoice_applicable_from = frappe.db.get_value("Company", company.name, ["is_einvoice_applicable", "einvoice_applicable_from"])

    if not is_einvoice_applicable == 1:
        frappe.throw("EInvoice Not Applicable")

    if frappe.utils.getdate(doc.get("posting_date")) < einvoice_applicable_from:
        frappe.throw(f"EInvoice Not Applicable before {einvoice_applicable_from}")

    if doc.get("mra_irn"):
        frappe.throw("EInvoice is already generated")

    if not company.tax_id:
        frappe.throw(f"Tax Id missing in Company <a href='/app/company/{company.name}'>{company.name}</a>")

    if not company.brn:
        frappe.throw(f"BRN missing in Company <a href='/app/company/{company.name}'>{company.name}</a>")

    if not company.legal_name:
        frappe.throw(f"Legal Name missing in Company <a href='/app/company/{company.name}'>{company.name}</a>")




def validate_before_submit(doc, target=None):
    company = frappe.get_doc("Company", doc.company)

    if company.is_einvoice_applicable == 1:
        if frappe.utils.getdate(doc.posting_date) >= frappe.utils.getdate(company.einvoice_applicable_from):
            if not doc.mra_irn:
                frappe.throw("Please generate einvoice before submitting this doc.")

