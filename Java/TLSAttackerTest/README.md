# TLSAttackerTest

Ce projet est un bac à sable (sandbox) permettant de se familiariser avec la bibliothèque **TLSAttacker** et de comprendre comment manipuler les échanges TLS.

## Contenu du Projet

Le projet contient deux classes principales situées dans `src/main/java/com/tlsclient/` :

1.  **TLSMessageLogger** : 
    *   **Rôle** : Utilisé pour observer et logger les échanges TLS standards.
    *   **Usage** : Permet de comprendre comment structurer les workflows de messages et comment TLSAttacker capture les informations durant la session.
2.  **ClientServerHelloTests** : 
    *   **Rôle** : Utilisé pour tester la reception des autres types de ServerHello
    *   **Usage** : Permet d'expérimenter avec la modification des paramètres TLS pour voir comment le système réagit.

## Configuration du point d'entrée (pom.xml)

Pour exécuter l'une ou l'autre de ces classes via Maven, vous devez modifier la configuration du plugin `exec-maven-plugin` dans le fichier `pom.xml`.

Recherchez la balise `<mainClass>` et modifiez son contenu selon vos besoins :

### Pour exécuter ClientServerHelloTests (par défaut actuellement) :
```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    ...
    <configuration>
        <mainClass>com.tlsclient.ClientServerHelloTests</mainClass>
    </configuration>
</plugin>
```

### Pour exécuter TLSMessageLogger :
```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>exec-maven-plugin</artifactId>
    ...
    <configuration>
        <mainClass>com.tlsclient.TLSMessageLogger</mainClass>
    </configuration>
</plugin>
```

Une fois le fichier sauvegardé, vous pouvez lancer l'exécution avec :
```bash
./run.sh
```
