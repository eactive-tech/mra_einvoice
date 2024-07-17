frappe.ui.form.on('Sales Invoice', {
    refresh(frm) {
        if(frm.doc.docstatus == 0 && !frm.doc.__islocal) {
            frm.add_custom_button("Generate eInvoice", function() {
                frappe.call("mra_einvoice.mra_einvoice.api.generate_einvoice", {
                    d: frm.doc,
                }).then(r => {
                    if (!r.exc) {
                        if (r.message.status === false) {
                            r.message.messages.forEach(e => {
                                frappe.msgprint({"message": e, "indicator": "red", "title": "MRA eInvoice Errors"})
                            })
                        }

                        if (r.message.status === true) {
                            frappe.msgprint({"message": r.message.messages, "indicator": "green", "title": "eInvoice Generated"})
                            frm.refresh()
                        }
                    }
                })
            })
        }
    }

})