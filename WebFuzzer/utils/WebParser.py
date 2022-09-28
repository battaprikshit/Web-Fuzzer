class HTMLParser():
    def __init__(self):
        self.action = ""
        self.fields = {}
        self.select = []
    

    def parseForm(self, extractedForm):
        self.action = extractedForm.get("action")
        ## get all input fields
        input_fields = extractedForm.find_all("input")
        for field in input_fields:
            field_name = field.get("name")
            field_type = field.get("type")
            if field_name and field_type:
                self.fields[field_name] = field_type
        
        ## get all select fields
        select_fields = extractedForm.find_all("select")
        for field in select_fields:
            self.fields[field.get("name")] = []
            select_options = field.find_all("option")
            for option in select_options:
                self.fields[field.get("name")].append(option.get("value"))
    