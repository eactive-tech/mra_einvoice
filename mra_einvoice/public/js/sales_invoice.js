frappe.ui.form.on('Sales Invoice', {
    refresh(frm) {
        if(frm.doc.docstatus == 0 && !frm.doc.__islocal) {
            frm.add_custom_button("Generate eInvoice", function() {
                frappe.call("mra_einvoice.mra_einvoice.api.generate_einvoice", {
                    d: frm.doc,
                })
            })
        }
    }

})