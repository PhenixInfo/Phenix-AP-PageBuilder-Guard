# Phenix AP PageBuilder Guard 1.1.10

Module communautaire de durcissement défensif pour les anciennes branches **AP Page Builder / `appagebuilder` 2.2.0 à 2.4.9**, destiné aux boutiques **PrestaShop 1.7.x à 8.x** qui ne peuvent pas encore migrer vers la branche officielle corrigée.

Le module ne modifie pas artificiellement le numéro de version d'AP Page Builder.

## Objectif

Le Guard apporte une mitigation locale, simple et réversible autour de points d'entrée historiques d'AP Page Builder :

- SQL injections documentées dans les anciennes branches ;
- CVE-2024-6648 / `product_item_path` / traversal via `config` Base64 ;
- écriture de templates et risque ApGenCode / SSTI / arbitrary file write ;
- primitives Smarty capables de déposer ou d'exécuter du PHP ;
- ancien téléchargement HTTP distant non vérifié de `updateBreadcrumb()` ;
- journalisation des blocages pour l'analyse d'attaque et les faux positifs.

Une mise à jour officielle vers une version corrigée d'AP Page Builder reste préférable dès qu'elle est compatible avec la boutique.

## Compatibilité

- PrestaShop : **1.7.x à 8.x** ;
- AP Page Builder : **2.2.0 à 2.4.9** pour le patch automatique ;
- AP Page Builder hors de cette plage : détection, informations et scanner restent accessibles, mais le patch automatique est désactivé.

Archives réellement rejouées pendant la validation de la 1.1.9 : **2.4.1, 2.4.3, 2.4.5 et 2.4.8**. Les autres versions de la plage restent gérées par détection structurelle et arrêt sûr si le point d'insertion n'est pas reconnu.

La version AP Page Builder est détectée dans cet ordre :

1. `modules/appagebuilder/appagebuilder.php` ;
2. `modules/appagebuilder/config.xml` ;
3. instance du module PrestaShop en dernier recours.

## Journal de sécurité

Les blocages générés par le Guard, par exemple `token AJAX invalide`, `liste numerique invalide`, `product_item_path interdit` ou `template Smarty dangereux`, sont écrits dans un fichier **JSONL**.

Aucune table SQL et aucun `PrestaShopLogger` ne sont utilisés.

Emplacement :

```text
/var/phappagebuilderguard/logs/security.log
```

Chaque événement contient notamment :

- date ISO 8601 ;
- type d'événement ;
- raison du blocage ;
- IP issue de `REMOTE_ADDR` ;
- méthode HTTP ;
- URL ;
- paramètres GET/POST filtrés.

Les champs sensibles connus sont masqués avant écriture : mots de passe, tokens, cookies, sessions, secrets, clés API, CSRF et champs de paiement courants.

`CF-Connecting-IP`, `X-Forwarded-For` et `X-Real-IP` peuvent être conservés séparément à titre informatif, mais ne sont jamais considérés comme fiables sans configuration explicite d'un proxy de confiance.

Limites :

- 2 Mo par fichier ;
- 3 rotations maximum ;
- valeurs et payloads bornés ;
- répertoire protégé par permissions, `.htaccess` et `index.php`.

Le journal est consultable et effaçable depuis l'onglet **Journal**.

## Protections appliquées

### `apajax.php`

Le Guard est chargé avant les traitements historiques d'AP Page Builder.

Il :

- reproduit le contrôle de token uniquement lorsque la variante installée l'utilise déjà ;
- ne force donc pas arbitrairement ce contrôle sur les anciennes branches où le flux AJAX diffère ;
- valide les listes numériques historiques (`product_all_one_img`, `image_product`, `product_manufacture`, `product_attribute_one_img`, etc.) ;
- contrôle les shortcodes AJAX suspects ;
- borne le traitement de la galerie ;
- contrôle le paramètre `config` Base64 et les traversals/wrappers.

### `ApProductList.php`

Le Guard :

- nettoie la configuration décodée avant utilisation ;
- refuse `product_item_path` fourni par la requête ;
- migre les anciennes variantes vulnérables vers le stockage serveur par cookie utilisé par le correctif PrestaShop ;
- borne ensuite le chemin de template à des emplacements AP Page Builder/thème attendus.

### `ApPageSetting.php`

L'écriture de fichier passe par un contrôle central avant `fopen/fwrite`.

Pour les `.tpl`, les noms de fichiers, chemins et motifs Smarty dangereux sont contrôlés.

### `ApGenCode.php`

Lorsque le motif historique `content_html` + génération de `.tpl` est détecté, le Guard valide :

- le nom du fichier généré ;
- le chemin ;
- le contenu Smarty avant écriture.

Cette protection fait suite à l'alerte publiée par LeoTheme en 2026 concernant une RCE non authentifiée via ApGenCode / SSTI / arbitrary file write. Le périmètre de versions exact n'est pas publié clairement dans la page publique actuellement accessible : le Guard applique donc une détection basée sur le code réellement installé.

### `updateBreadcrumb()`

L'ancien téléchargement de fichiers depuis une URL HTTP distante non signée/non vérifiée est désactivé lorsqu'il est détecté.

## Scanner

Le scanner intégré est volontairement limité à :

```text
/modules/appagebuilder/
```

Il ne scanne jamais :

- la racine PrestaShop ;
- les autres modules ;
- `themes/` ;
- `var/` ;
- les zones d'upload.

Cette limite est volontaire afin que le Guard reste un patch ciblé et non un scanner malware généraliste.

Conséquence : un fichier compromis déjà présent dans :

```text
/themes/<theme>/modules/appagebuilder/
```

ou à la racine du site n'est pas couvert par ce scanner.

## Sauvegardes et restauration

Deux mécanismes sont volontairement séparés.

### Sauvegarde manuelle

L'onglet **Maintenance** propose **Créer une sauvegarde maintenant**. Cette action copie les fichiers AP Page Builder gérés par le Guard dans un snapshot horodaté :

```text
/var/phappagebuilderguard/backups/manual/<date>/
```

La dernière sauvegarde manuelle peut être restaurée depuis le même écran. Avant restauration, le Guard conserve aussi une copie de l'état courant. Le manifeste contient les checksums SHA-256 des fichiers sauvegardés et la restauration refuse tout chemin extérieur à `/modules/appagebuilder/`.

### Rollback automatique du patch

Avant toute modification réalisée par le patch, le fichier original est sauvegardé dans :

```text
/var/phappagebuilderguard/backups/
```

Les anciennes sauvegardes du Guard stockées dans :

```text
/modules/phappagebuilderguard/backups/
```

restent reconnues.

Le rollback du patch est volontairement distinct de la sauvegarde manuelle : une sauvegarde créée après application du patch ne remplace donc jamais le fichier original utilisé pour retirer le patch.

Désactiver le module PrestaShop ne retire pas les modifications physiques déjà appliquées. Pour retirer proprement le patch :

1. restaurer le dernier backup ;
2. vérifier le front et le back-office AP Page Builder ;
3. vider le cache PrestaShop / Smarty ;
4. désactiver ou supprimer ensuite le Guard si nécessaire.

## Installation

1. installer le ZIP depuis le gestionnaire de modules ;
2. ouvrir **Phenix AP PageBuilder Guard** ;
3. vérifier la version AP Page Builder détectée ;
4. si le patch est incomplet et la branche supportée, cliquer sur **Appliquer le patch** ;
5. vérifier que l'état devient **Patch actif** ;
6. tester le front, les listes produits, le « show more », les profils AP Page Builder et le back-office ;
7. vider le cache PrestaShop / Smarty.

Une fois le patch actif, le bouton **Appliquer le patch** disparaît.

## Sources de sécurité

Les décisions de patch reposent d'abord sur des sources publiques traçables. Les URL utilisées dans l'onglet **Informations** ont été revérifiées en septembre 2026.

- LeoTheme — centre AP Page Builder : `https://blog.leotheme.com/prestashop-module-tutorials/ap-page-builder` ;
- LeoTheme — correctif RCE ApGenCode 2026 ;
- LeoTheme — correctif SSTI / Path Traversal 2026 ;
- LeoTheme — avis SQLi AP PageBuilder 2.2.4 ;
- Friends Of Presta — CVE-2022-22897, SQL injections ;
- NVD — CVE-2022-22897 ;
- NVD — CVE-2022-44897, XSS `show_number` ;
- NVD — CVE-2023-3743, SQLi `product_one_img` ;
- Friends Of Presta / NVD — CVE-2024-6648, traversal ;
- PrestaShop Help Center — correction officielle `product_item_path` et recommandation de mise à jour en 4.0.0.

Les discussions de forums et contenus communautaires peuvent servir de signal, mais ne sont pas utilisés comme autorité pour modifier automatiquement le code lorsqu'ils ne sont pas corroborés par une source technique fiable.

### Nuance CVE-2022-22897

Le record CVE/NVD historique décrit notamment `product_all_one_img` et `image_product` jusqu'à 2.4.4. L'avis Friends Of Presta a ensuite été enrichi et publie des corrections pour les versions jusqu'à 2.4.5 ainsi que des variantes plus anciennes. Le Guard suit cette couverture mise à jour pour la branche 2.2 à 2.4.5.

### CVE-2024-6648

L'avis INCIBE-CERT indique que toutes les versions antérieures à 4.0.0 sont concernées et que la correction officielle est en 4.0.0. Ce Guard ne prétend pas remplacer cette mise à jour : il fournit une mitigation pour les branches 2.2 à 2.4.9.

## Site déjà compromis

Le Guard n'est pas un outil de nettoyage global. Après une compromission, il faut également contrôler la racine, le thème, les autres modules, les caches, les comptes administrateurs, les accès FTP/SSH et les fichiers récemment modifiés.

## Changelog

### 1.1.1

- ajout d'un `logo.png` dédié au module ;
- ajout d'une vraie sauvegarde manuelle et de sa restauration, distinctes du rollback pré-patch ;
- validation réelle sur les archives AP Page Builder 2.4.1, 2.4.3, 2.4.5 et 2.4.8 fournies ;
- URLs LeoTheme revérifiées depuis le centre AP Page Builder et liens directs corrigés ;
- documentation CVE enrichie avec CVE-2022-44897 et CVE-2023-3743 ;
- compatibilité déclarée PrestaShop 1.7.x à 8.x ;
- patch automatique borné AP Page Builder 2.2.0 à 2.4.9 ;
- détection de version AP Page Builder ;
- adaptation du contrôle token aux variantes réellement installées ;
- durcissement SQLi historique élargi ;
- mitigation CVE-2024-6648 ;
- protection ApGenCode / SSTI / arbitrary file write ;
- journal JSONL sans base de données, rotation et masquage des secrets ;
- nouvel onglet Journal ;
- nouvel onglet Informations avec sources et compatibilité ;
- scanner toujours strictement limité à `/modules/appagebuilder/`.


## Validation PrestaShop

La version 1.1.9 traite les sections **Optimizations** et **Standards** du Validator :

- tout le HTML du back-office est rendu depuis `views/templates/` avec Smarty ;
- les confirmations sont gérées par `views/js/admin.js` et non plus par du HTML/JavaScript construit en PHP ;
- les tableaux PHP utilisent la syntaxe courte `[]` ;
- les constantes de classe ont une visibilité explicite ;
- les règles de style signalées (`increment_style`, `single_quote`, `blank_line_after_opening_tag`, `no_alias_language_construct_call`, `no_blank_lines_after_phpdoc`, `blank_line_before_statement`) ont été reprises ;
- les nouveaux répertoires `views/templates/` et `views/js/` disposent de fichiers `index.php` protégés.

## Qualite et validation

La branche 1.1.9 a fait l objet d une passe specifique de validation communautaire :

- fichiers UTF-8 sans BOM, fins de ligne LF et ligne finale ;
- en-tetes `@author`, `@copyright` et `@license` sur tous les fichiers PHP ;
- controle CSRF explicite des actions de maintenance ;
- ecritures et restaurations atomiques des fichiers AP Page Builder ;
- CSS d administration consolide sans selecteurs racine dupliques ;
- aucun SQL, aucune table additionnelle, aucun service externe et aucune dependance Composer runtime ;
- tests de patch/rollback sur les archives AP Page Builder 2.4.1, 2.4.3, 2.4.5 et 2.4.8 fournies pour validation.

Le code conserve volontairement une syntaxe compatible avec les anciennes branches PrestaShop 1.7.0-1.7.3, qui peuvent fonctionner sous PHP 5.4. Par consequent, le module n utilise pas `declare(strict_types=1)` ni les types de retour introduits avec PHP 7.
