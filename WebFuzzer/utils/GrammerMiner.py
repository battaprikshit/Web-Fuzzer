import gramfuzz
from html.parser import HTMLParser
from gramfuzz.fields import *
from utils.grammar import base_grammar 

class GenerateGrammar():
    def __init__(self, webparser, attackType):
        self.base_grammar = base_grammar
        self.attack_type = attackType
        self.grammar_rules = self.createNewRules(webparser)

    def createNewRules(self,webparser):
        newRules = []
        actionGramRule = 'UDef("action", Or("' + webparser.action+'"))'
        newRules.append(actionGramRule)

        requestParams = ['URef("'+ key +'")' for key in webparser.fields.keys()]
        queryRule = 'UDef("query",'+ ",".join(requestParams) + ",sep='&')"
        newRules.append(queryRule)

        for field in webparser.fields:
            fieldName = field
            fieldType = webparser.fields[fieldName]
            if fieldType == "submit":
                self.submit_field_name = fieldName
                newRules.append('UDef("'+fieldName+'", Or("'+ fieldName +'"), Or("go"), sep="=")')

            if fieldType == "text" or fieldType == "password":
                if self.attack_type == "XSS":
                    self.xss_field_name = fieldName
                    newRules.append('UDef("'+fieldName+'", Or("'+ fieldName +'"), URef("_xss_string"), sep="=")')
                elif self.attack_type == "SQLI":
                    newRules.append('UDef("'+fieldName+'", Or("'+ fieldName +'"), URef("_sql_string"), sep="=")')
            
        newRuleJoin = "\n".join(newRules)
        updateGrammar = "\n".join([base_grammar, newRuleJoin])
        # print(PAGE_GRAMMAR)
        with open('GeneratedGrammar.py', 'w') as f:
            f.write(updateGrammar)
        return updateGrammar
