1 2 3

# README 
# MARIN MARIUS DANIEL 332CC
## [Tema1 - RL](https://gitlab.cs.pub.ro/rl/tema1-public)


### Implementare:
* s-au rezolvat urmatoarele 3 functii:
    - `tabela de comutare`
    - `vlan`
    - `stp`

### Pentru
* `tabela de comutare`
    - s-a creat un dictionar global pentru fiecare switch in
    care se mapeaza o intrare de forma (mac, port)
    - se adauga mac-ul sursa si portul in dictionar de la fiecare
    pachet primit
    - se verifica daca exista deja o intrare pentru mac-ul destinatie,
    altfel se trimite pachetul pe toate celelalte porturi
    - implementarea este conform pseudocodului din enunt

* `vlan`
    - s-a creat o functie care primeste ca parametru switch id ul,
    si realizeaza parsarea fisierului de configurare corespunzator
    acestuia
    - se verifica daca pachetul primit vine de pe o interfata acces/
    trunk si se ia apoi in considerare pe ce fel de interfata se trimite
    - se implementeaza astfel cazurile posibile explicate in enunt

* `stp`
    - pentru stp s-au mai adaugat niste vectori globali ce contin informatii
    legate de starea si tipul fiecarui port de pe un switch
    - pentru formarea cadrului bdpu s-a creat o functie speciala care face
    impachetarea datelor folosind struct pack (s-au folosit doar campurile
    root bridge id, root path cost, bridge id, port id)
    - la extragerea informatiilor din cadrul bdpu s-a folosit struct unpack
    - partea de trimitere a cadrului bdpu este conform pseudocodului din enunt
    (doar root bridge-ul trimite cadre bdpu)
    - partea de tratare a unui bdpu cand este primit este conform pseudocodului
    din enunt

### Mai multe detalii se regasesc in cod.