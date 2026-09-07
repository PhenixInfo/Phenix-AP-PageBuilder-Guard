# Phenix AP PageBuilder Guard 1.1.17

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
- PHP : **7.1 minimum** (la visibilité explicite des constantes, exigée par les standards Validator, nécessite PHP 7.1+) ;
- AP Page Builder : **2.2.0 à 2.4.9** pour le patch automatique ;
- AP Page Builder hors de cette plage : détection, informations et scanner restent accessibles, mais le patch automatique est désactivé.

Archives réellement rejouées pendant la validation de la 1.1.17 : **2.4.1, 2.4.3, 2.4.5 et 2.4.8**, plus une variante client hybride déclarée 2.4.8 dans `config.xml` mais modifiée localement (`json_decode` dans `ApProductList.php`, version PHP déclarée 4.0.0). Cette archive hybride est utilisée uniquement comme fixture externe de régression et n'est pas redistribuée. Les autres versions de la plage restent gérées par détection structurelle et arrêt sûr si le point d'insertion n'est pas reconnu.

La version AP Page Builder est détectée dans cet ordre :

1. `modules/appagebuilder/appagebuilder.php` ;
2. `modules/appagebuilder/config.xml` ;
3. instance du module PrestaShop en dernier recours.

## Journal de sécurité

Les blocages générés par le Guard, par exemple `token AJAX invalide`, `liste numerique invalide`, `product_item_path interdit` ou `template Smarty dangereux`, sont écrits dans un fichier **JSONL**.

Aucune table SQL et aucun `PrestaShopLogger` ne sont utilisés.

Emplacement :

```text
/var/phappagebuilderguard/logs/security.log.php
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
- répertoire protégé par permissions, `.htaccess` et `index.php` ;
- le fichier courant commence par un garde PHP `exit`, afin de réduire le risque d’exposition directe sur une configuration nginx personnalisée qui ne lit pas `.htaccess`.

Le journal est consultable et effaçable depuis l'onglet **Journal**.





## Ajustements 1.1.17

- Compatibilité de patch avec une variante client hybride d'AP Page Builder basée sur 2.4.8 qui remplace `Tools::jsonDecode(...)` par `json_decode(...)` dans `ApProductList.php`.
- Le point d'insertion Base64/config accepte désormais exclusivement ces deux formes équivalentes et conserve le même garde `sanitizeApProductListInput()`.
- Aucun élargissement du périmètre scanner ni des écritures autorisées.
- Ajout de cette variante comme cas de régression externe : l'archive cliente n'est pas embarquée ni redistribuée dans le projet.

## Ajustements 1.1.16

Release de conformité PrestaShop Validator uniquement. Aucun changement de logique sécurité. Le commentaire de licence du fichier principal est replacé immédiatement après `<?php`, sans ligne vide, conformément au contrôle **Licenses** du Validator. Cette contrainte de packaging prévaut pour ce fichier sur le signal contradictoire `blank_line_after_opening_tag` observé précédemment dans **Standards**.

## Ajustements 1.1.15

Release de conformité PrestaShop Validator uniquement. Aucun changement de logique sécurité : application des règles PHP CS Fixer remontées sur `phappagebuilderguard.php` (`class_attributes_separation`, `blank_line_after_opening_tag`, `no_extra_blank_lines`, `blank_line_before_statement`, `single_blank_line_at_eof`).

## Ajustements 1.1.14

La 1.1.14 traite les derniers résiduels de la revue 1.1.12 sans élargir la surface fonctionnelle :

- filet SQLi générique resserré pour ne plus bloquer des phrases anglaises légitimes comme `Select from our new collection`, `Insert into your basket`, `Sleep (Deluxe Edition)` ou `1 and 1=1` ;
- détection galerie tolérante à la casse en défense en profondeur ;
- `show_number` tableau/objet rejeté avant toute conversion en chaîne, sans warning PHP ;
- documentation du marqueur `_PRODUCTLIST_STORAGE_` corrigée : il est obligatoire pour le statut `Patch actif` ;
- mise à jour depuis une ancienne branche patchée : si le marqueur STORAGE manque, le statut devient volontairement `Patch incomplet` et il faut relancer le patch après sauvegarde ;
- les écritures `.js`, `.css` et `.xml` restent autorisées car les quatre archives AP testées les utilisent réellement pour les profils/positions/export. Le Guard bloque le PHP/webshell serveur, mais ne tente pas d'interpréter le JavaScript/CSS métier du page builder.

## Audit renforcé 1.1.13

La 1.1.13 est issue d'une passe séparée de simplification, revue de code et audit sécurité/fuzzing :

- le scanner refuse désormais les fichiers/liens symboliques et vérifie le `realpath()` de chaque fichier avant lecture afin de ne jamais sortir de `/modules/appagebuilder/` ;
- le garde générique d'écriture refuse une cible existante qui est un lien symbolique ;
- le filet SQLi des paramètres AJAX inconnus inspecte la valeur complète, sans ancienne coupure à 4 Kio ;
- les commentaires SQL `/**/` et commentaires conditionnels MySQL sont normalisés avant la détection haute confiance ;
- suppression du manifeste post-patch inutilisé, de champs AP calculés mais jamais affichés et de plusieurs helpers à appel unique/relectures disque inutiles ;
- la suite de fuzzing déterministe couvre maintenant plus de 800 cas, dont les paramètres SQLi connus, mutations de casse/espaces/commentaires, préfixes longs, symlinks, chemins de template et sauvegarde/restauration manuelle exacte.

Les sauvegardes automatiques avant patch, le rollback pré-patch et les sauvegardes manuelles restent inchangés et obligatoires.

## Simplifications 1.1.12

La 1.1.12 recentre le module sur son rôle de **patch/guard** :

- suppression complète de la quarantaine et de sa restauration ;
- scanner désormais explicitement **100 % lecture seule** ;
- aucune suppression, aucun déplacement et aucune modification de fichier par le scanner ;
- la quarantaine/remédiation reste du ressort d'un scanner malware dédié ;
- suppression des niveaux `severity` / `confidence` qui étaient constants pour toutes les signatures du scanner ;
- suppression de l'abstraction `getScanRoots()` alors que le périmètre est volontairement unique et fixe ;
- simplification de la création du répertoire de sauvegarde.

Ces suppressions réduisent la surface de code et le risque opérationnel sans modifier les protections runtime ni le mécanisme de patch/rollback.

## Durcissements 1.1.11

La 1.1.11 intègre les corrections issues d'une revue externe approfondie :

- aucune écriture `.php`, `.phtml`, `.htaccess` ou extension inconnue via `ApPageSetting::writeFile()` ;
- aucun court-circuit `leoajax=1` des contrôles `show_number` ou `config` ;
- faux positifs `Pack (`, `Touch (`, `Copy (` et `{insert}` supprimés ;
- `form_id` absent ne provoque plus un 403 ;
- `product_item_path` ne fait plus confiance à `$_COOKIE` brut ;
- résolution des templates indépendante du répertoire de travail PHP ;
- statut de patch exige aussi les marqueurs `_PRODUCTLIST_STORAGE_` ;
- historique : la 1.1.11 avait introduit une quarantaine réversible ; cette fonctionnalité a été entièrement supprimée en 1.1.12 au profit d'un scanner strictement en lecture seule.

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

Le scanner intégré est **en lecture seule** et volontairement limité à :

```text
/modules/appagebuilder/
```

Il ne scanne jamais :

- la racine PrestaShop ;
- les autres modules ;
- `themes/` ;
- `var/` ;
- les zones d'upload.

Cette limite est volontaire afin que le Guard reste un patch ciblé et non un scanner malware généraliste. Le scanner n'a aucune action de quarantaine ou de suppression : il signale uniquement les correspondances afin qu'elles soient examinées avec l'outil malware dédié.

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
