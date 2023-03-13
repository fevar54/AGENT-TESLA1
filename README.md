# AGENT-TESLA1
La siguiente regla YARA buscará coincidencias con los hashes y valores, 
si encuentra alguna coincidencia, se generará una alerta indicando la posible presencia de Agent Tesla

Esta regla busca cualquier archivo que contenga uno o más de los valores de hash especificados en la regla 
y se activará si encuentra al menos uno de ellos en el archivo analizado. 
