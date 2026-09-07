<?php
/**
 * Phenix AP PageBuilder Guard.
 *
 * Defensive hardening module for AP Page Builder / appagebuilder.
 * Compatible with PrestaShop 1.7.x to 8.x.
 *
 * @author Phenix Info
 * @copyright 2026 Phenix Info
 * @license https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once dirname(__FILE__) . '/classes/PhApPageBuilderGuard.php';

class PhApPageBuilderGuard extends Module
{
    public const CONFIG_ENABLED = 'PHAPB_GUARD_ENABLED';
    public const PATCH_MARKER = 'PHENIX_APPAGEBUILDER_GUARD';

    /** @var array|null Cache des informations AP Page Builder pour la requete courante. */
    private $apPageBuilderInfoCache;

    public function __construct()
    {
        $this->name = 'phappagebuilderguard';
        $this->tab = 'administration';
        $this->version = '1.1.17';
        $this->author = 'Phenix Info';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = ['min' => '1.7.0.0', 'max' => '8.99.99'];

        parent::__construct();

        $this->displayName = $this->l('Phenix AP PageBuilder Guard');
        $this->description = $this->l('Security hardening patch for AP Page Builder 2.2 to 2.4.9: SQL injection, path traversal, ApGenCode/SSTI, security logs and targeted scanning.');
        $this->confirmUninstall = $this->l('Uninstall the protection module? Patched AP Page Builder files will not be restored automatically. Use the restore feature first if required.');
    }

    public function install()
    {
        return parent::install()
            && Configuration::updateValue(self::CONFIG_ENABLED, 1)
            && $this->registerHook('displayBackOfficeHeader')
            && $this->ensureWritableDirs();
    }

    public function uninstall()
    {
        Configuration::deleteByName(self::CONFIG_ENABLED);

        return parent::uninstall();
    }

    public function hookDisplayBackOfficeHeader($params)
    {
        unset($params);

        if (!$this->active || !Configuration::get(self::CONFIG_ENABLED)) {
            return '';
        }

        $controller = (string) Tools::getValue('controller');
        $isApPageBuilder = strpos($controller, 'AdminApPageBuilder') !== false;
        $isDashboard = $controller === 'AdminDashboard';
        $isGuardPage = $controller === 'AdminModules' && (string) Tools::getValue('configure') === $this->name;
        if (!$isApPageBuilder && !$isDashboard && !$isGuardPage) {
            return '';
        }

        $status = $this->getPatchStatus();
        if ($status['patched']) {
            return '';
        }

        $this->loadAdminAssets();
        $this->context->smarty->assign('phapb_warning', [
            'message' => $this->l('Phenix AP PageBuilder Guard : le patch defensif appagebuilder n est pas completement applique.'),
            'url' => $this->context->link->getAdminLink('AdminModules', true, [], ['configure' => $this->name]),
            'link_label' => $this->l('Ouvrir le module'),
        ]);

        return $this->display(__FILE__, 'views/templates/hook/backoffice_warning.tpl');
    }

    public function getContent()
    {
        $this->ensureWritableDirs();
        $this->loadAdminAssets();
        $messages = [];
        $errors = [];
        $scan = null;

        try {
            if ($this->hasMutatingRequest()) {
                $this->assertValidAdminToken();
            }

            if (Tools::isSubmit('phapb_save')) {
                $enabled = (int) Tools::getValue('PHAPB_GUARD_ENABLED', 1);
                if (!in_array($enabled, [0, 1], true)) {
                    throw new Exception('Valeur de configuration invalide.');
                }
                Configuration::updateValue(self::CONFIG_ENABLED, $enabled);
                $messages[] = $this->l('Configuration enregistree.');
            }

            if (Tools::isSubmit('phapb_clear_logs')) {
                $count = PhApPageBuilderGuardCore::clearLogs();
                $messages[] = sprintf($this->l('Journal nettoye : %d fichier(s) supprime(s).'), $count);
            }

            if (Tools::isSubmit('phapb_patch')) {
                $result = $this->applyPatch();
                $messages = array_merge($messages, $result);
            }

            if (Tools::isSubmit('phapb_backup_now')) {
                $result = $this->createManualBackup();
                $messages = array_merge($messages, $result);
            }

            if (Tools::isSubmit('phapb_restore_manual')) {
                $result = $this->restoreLatestManualBackup();
                $messages = array_merge($messages, $result);
            }

            if (Tools::isSubmit('phapb_restore')) {
                $result = $this->restoreLastBackups();
                $messages = array_merge($messages, $result);
            }

            if (Tools::isSubmit('phapb_scan')) {
                $scan = PhApPageBuilderGuardCore::scanInstallation();
                $messages[] = sprintf($this->l('Scan termine : %d alerte(s).'), count($scan));
            }
        } catch (Exception $e) {
            $errors[] = $e->getMessage();
        }

        $status = $this->getPatchStatus();

        return $this->renderDashboard($status, $scan, $messages, $errors);
    }

    /**
     * Indique si la requete courante declenche une action modifiant des fichiers
     * ou la configuration du module.
     *
     * @return bool
     */
    private function hasMutatingRequest()
    {
        foreach ([
            'phapb_save',
            'phapb_clear_logs',
            'phapb_patch',
            'phapb_backup_now',
            'phapb_restore_manual',
            'phapb_restore',
        ] as $action) {
            if (Tools::isSubmit($action)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verifie explicitement le jeton du controleur AdminModules avant toute
     * operation destructive ou persistante.
     *
     * @throws Exception
     */
    private function assertValidAdminToken()
    {
        $token = (string) Tools::getValue('token', '');
        $expected = (string) Tools::getAdminTokenLite('AdminModules');

        if ($token === '' || $expected === '' || $token !== $expected) {
            throw new Exception('Jeton administrateur invalide. Action refusee.');
        }
    }

    /**
     * Charge uniquement la feuille de style de la page de configuration.
     * Aucun CDN ni dependance JavaScript externe.
     */
    private function loadAdminAssets()
    {
        if (!isset($this->context->controller)) {
            return;
        }

        if (method_exists($this->context->controller, 'addCSS')) {
            $this->context->controller->addCSS($this->_path . 'views/css/admin.css');
        }
        if (method_exists($this->context->controller, 'addJS')) {
            $this->context->controller->addJS($this->_path . 'views/js/admin.js');
        }
    }

    /**
     * Render the module dashboard through Smarty.
     *
     * @param array $status
     * @param array|null $scan
     * @param array $messages
     * @param array $errors
     *
     * @return string
     */
    private function renderDashboard(array $status, $scan, array $messages, array $errors)
    {
        $enabled = (int) Configuration::get(self::CONFIG_ENABLED);
        $apInfo = $this->getApPageBuilderInfo();
        $hasBackup = $this->hasAnyBackup();
        $manualBackup = $this->getLatestManualBackupInfo();
        $activeTab = (string) Tools::getValue('phapb_tab', 'overview');
        $allowedTabs = ['overview', 'logs', 'scan', 'maintenance', 'information'];

        if (!in_array($activeTab, $allowedTabs, true)) {
            $activeTab = 'overview';
        }

        $baseParams = ['configure' => $this->name];
        $urls = [
            'overview' => $this->context->link->getAdminLink('AdminModules', true, [], array_merge($baseParams, ['phapb_tab' => 'overview'])),
            'logs' => $this->context->link->getAdminLink('AdminModules', true, [], array_merge($baseParams, ['phapb_tab' => 'logs'])),
            'scan' => $this->context->link->getAdminLink('AdminModules', true, [], array_merge($baseParams, ['phapb_tab' => 'scan'])),
            'maintenance' => $this->context->link->getAdminLink('AdminModules', true, [], array_merge($baseParams, ['phapb_tab' => 'maintenance'])),
            'information' => $this->context->link->getAdminLink('AdminModules', true, [], array_merge($baseParams, ['phapb_tab' => 'information'])),
        ];
        $versionLabel = $apInfo['installed'] ? ($apInfo['version'] !== '' ? $apInfo['version'] : $this->l('version inconnue')) : $this->l('non detecte');
        $view = [
            'version' => $this->version,
            'ps_version' => _PS_VERSION_,
            'logo_url' => $this->_path . 'logo.png',
            'admin_token' => Tools::getAdminTokenLite('AdminModules'),
            'messages' => $messages,
            'errors' => $errors,
            'status' => $status,
            'enabled' => (bool) $enabled,
            'has_backup' => $hasBackup,
            'manual_backup' => $manualBackup,
            'ap' => $apInfo,
            'active_tab' => $activeTab,
            'urls' => $urls,
            'tabs' => $this->buildTabsView($activeTab, $urls),
            'labels' => $this->buildLabelsView(),
            'confirm' => $this->buildConfirmView(),
            'hero' => [
                'description' => $this->l('Module de mitigation pour AP Page Builder 2.2 a 2.4.9 sur PrestaShop 1.7.x a 8.x : patch defensif, journal fichier, scanner cible et outils de sauvegarde / restauration.'),
                'version_label' => $versionLabel,
                'branch_label' => $apInfo['supported'] ? $this->l('Branche supportee') : $this->l('Branche hors perimetre'),
                'can_patch' => $apInfo['installed'] && $apInfo['supported'],
                'patch_label' => $status['patched'] ? $this->l('Patch actif') : $this->l('Patch incomplet'),
                'patch_message' => $status['patched'] ? $this->l('Les protections attendues pour cette installation sont presentes.') : $this->l('Une ou plusieurs protections attendues sont absentes.'),
                'runtime_label' => $enabled ? $this->l('Protection active') : $this->l('Protection desactivee'),
                'backup_label' => $hasBackup ? $this->l('Rollback disponible') : $this->l('Aucun rollback'),
                'support_label' => $apInfo['supported'] ? $this->l('AP 2.2 - 2.4.9 supporte') : $this->l('Version AP non supportee'),
            ],
            'overview' => $this->buildOverviewView($status, $enabled, $hasBackup, $apInfo, $urls),
            'logs' => $activeTab === 'logs' ? $this->buildLogsView() : [],
            'scan' => $activeTab === 'scan' ? $this->buildScanView($scan) : [],
            'maintenance' => $this->buildMaintenanceView($status, $enabled, $manualBackup),
            'information' => $activeTab === 'information' ? $this->buildInformationView($apInfo, $status) : [],
        ];

        $this->context->smarty->assign('phapb', $view);

        return $this->display(__FILE__, 'views/templates/admin/dashboard.tpl');
    }

    /**
     * Build navigation data for Smarty.
     *
     * @param string $activeTab
     * @param array $urls
     *
     * @return array
     */
    private function buildTabsView($activeTab, array $urls)
    {
        return [
            ['key' => 'overview', 'label' => $this->l('Vue d ensemble'), 'icon' => '▦', 'url' => $urls['overview'], 'active' => $activeTab === 'overview'],
            ['key' => 'logs', 'label' => $this->l('Journal'), 'icon' => '☰', 'url' => $urls['logs'], 'active' => $activeTab === 'logs'],
            ['key' => 'scan', 'label' => $this->l('Scanner'), 'icon' => '⌕', 'url' => $urls['scan'], 'active' => $activeTab === 'scan'],
            ['key' => 'maintenance', 'label' => $this->l('Maintenance'), 'icon' => '⚙', 'url' => $urls['maintenance'], 'active' => $activeTab === 'maintenance'],
            ['key' => 'information', 'label' => $this->l('Informations'), 'icon' => 'ⓘ', 'url' => $urls['information'], 'active' => $activeTab === 'information'],
        ];
    }

    /**
     * Build translated labels shared by templates.
     *
     * @return array
     */
    private function buildLabelsView()
    {
        return [
            'apply_patch' => $this->l('Appliquer le patch'),
            'security_log' => $this->l('Journal de securite'),
            'scan_ap' => $this->l('Scanner AP Page Builder'),
            'rollback_patch' => $this->l('Rollback patch'),
            'view_information' => $this->l('Voir les informations'),
            'protection_state' => $this->l('Etat de la protection'),
            'navigation' => $this->l('Navigation du module'),
            'file_log' => $this->l('JOURNAL FICHIER'),
            'security_events' => $this->l('Evenements de securite AP Page Builder'),
            'events' => $this->l('evenement(s)'),
            'files' => $this->l('fichier(s)'),
            'date' => $this->l('Date'),
            'event' => $this->l('Evenement'),
            'method' => $this->l('Methode'),
            'reason' => $this->l('Raison'),
            'clear_log' => $this->l('Nettoyer le journal'),
            'empty_log' => $this->l('Vider le journal'),
            'no_logged_event' => $this->l('Aucun evenement journalise'),
            'ip_address' => $this->l('Adresse IP'),
            'targeted_analysis' => $this->l('ANALYSE CIBLEE'),
            'run_scan' => $this->l('Lancer le scan'),
            'results' => $this->l('RESULTATS'),
            'compliant' => $this->l('Conforme'),
            'no_alert' => $this->l('Aucune alerte detectee'),
            'type' => $this->l('Type'),
            'file' => $this->l('Fichier'),
            'line' => $this->l('Ligne'),
            'match' => $this->l('Indice'),
            'guard_protection' => $this->l('Protection du guard'),
            'runtime_protection' => $this->l('Protection runtime'),
            'enabled' => $this->l('Activee'),
            'disabled' => $this->l('Desactivee'),
            'save' => $this->l('Enregistrer'),
            'backup' => $this->l('SAUVEGARDE'),
            'backup_restore' => $this->l('Sauvegarde et restauration'),
            'create_backup' => $this->l('Creer une sauvegarde maintenant'),
            'restore_manual_backup' => $this->l('Restaurer la sauvegarde manuelle'),
            'automatic_rollback' => $this->l('Rollback automatique avant patch'),
            'restore_before_patch' => $this->l('Restaurer les fichiers avant patch'),
            'patch_integrity' => $this->l('INTEGRITE DU PATCH'),
            'important' => $this->l('Important'),
            'detected_installation' => $this->l('INSTALLATION DETECTEE'),
            'compatibility' => $this->l('COMPATIBILITE'),
            'protection_matrix' => $this->l('Matrice de protection'),
            'tested_archives' => $this->l('Archives reellement testees :'),
            'documented_vulnerabilities' => $this->l('VULNERABILITES DOCUMENTEES'),
            'cross_checked_sources' => $this->l('Sources recoupees'),
            'references' => $this->l('REFERENCES'),
            'official_documentation' => $this->l('Documentation et avis officiels'),
            'community_sources' => $this->l('Sources communautaires'),
            'limits' => $this->l('Limites'),
            'defence_in_depth' => $this->l('DEFENSE EN PROFONDEUR'),
            'applied_protections' => $this->l('Protections appliquees'),
            'operations' => $this->l('EXPLOITATION'),
            'control_maintenance' => $this->l('Controle et maintenance'),
            'scope' => $this->l('Perimetre'),
            'community_protection' => $this->l('Protection communautaire pour PrestaShop'),
        ];
    }

    /**
     * Build confirmation messages used by the small local JavaScript helper.
     *
     * @return array
     */
    private function buildConfirmView()
    {
        return [
            'patch' => $this->l('Appliquer le patch avec sauvegarde des fichiers originaux ?'),
            'rollback' => $this->l('Restaurer les derniers fichiers sauvegardes avant patch ? Le patch sera retire des fichiers restaures.'),
            'clear_logs' => $this->l('Supprimer le journal de securite et ses rotations ?'),
            'restore_manual' => $this->l('Restaurer la derniere sauvegarde manuelle ? Une copie de l etat actuel sera creee avant restauration.'),
        ];
    }

    /**
     * Build overview data.
     *
     * @param array $status
     * @param int $enabled
     * @param bool $hasBackup
     * @param array $apInfo
     * @param array $urls
     *
     * @return array
     */
    private function buildOverviewView(array $status, $enabled, $hasBackup, array $apInfo, array $urls)
    {
        $versionLabel = $apInfo['installed'] ? ($apInfo['version'] !== '' ? $apInfo['version'] : $this->l('Inconnue')) : $this->l('Non detecte');
        $alert = [];

        if (!$apInfo['installed']) {
            $alert = [
                'tone' => 'danger',
                'title' => $this->l('AP Page Builder absent'),
                'message' => $this->l('Le dossier /modules/appagebuilder/ ou une version exploitable du module n a pas ete detecte. Aucun patch fichier ne sera applique.'),
            ];
        } elseif (!$apInfo['supported']) {
            $alert = [
                'tone' => 'warning',
                'title' => $this->l('Version hors perimetre'),
                'message' => sprintf($this->l('La version detectee (%s) est en dehors de la branche 2.2.0 a 2.4.9. Le scanner et le journal restent utilisables mais le patch automatique est desactive.'), $versionLabel),
            ];
        } elseif (!$status['patched']) {
            $alert = [
                'tone' => 'danger',
                'title' => $this->l('Protection incomplete'),
                'message' => $this->l('Au moins un correctif attendu pour cette variante AP Page Builder est absent. Utilisez le bouton du bandeau pour appliquer le patch avec sauvegarde.'),
            ];
        }

        return [
            'metrics' => [
                ['label' => $this->l('Patch fichiers'), 'value' => $status['patched'] ? $this->l('Actif') : $this->l('Incomplet'), 'tone' => $status['patched'] ? 'success' : 'danger', 'detail' => $this->l('Verification des marqueurs reels')],
                ['label' => $this->l('Protection runtime'), 'value' => $enabled ? $this->l('Active') : $this->l('Desactivee'), 'tone' => $enabled ? 'success' : 'neutral', 'detail' => $this->l('Filtrage execute par le guard')],
                ['label' => $this->l('Rollback patch'), 'value' => $hasBackup ? $this->l('Disponible') : $this->l('Absent'), 'tone' => $hasBackup ? 'success' : 'neutral', 'detail' => $this->l('Copie automatique avant modification')],
                ['label' => $this->l('AP Page Builder'), 'value' => $versionLabel, 'tone' => $apInfo['supported'] ? 'success' : ($apInfo['installed'] ? 'danger' : 'neutral'), 'detail' => $apInfo['source'] !== '' ? $this->l('Detecte depuis ') . $apInfo['source'] : $this->l('Version actuellement installee')],
            ],
            'alert' => $alert,
            'protections_description' => $this->l('Le guard protege les points d entree historiques sans transformer AP Page Builder en nouvelle architecture.'),
            'protections' => [
                ['title' => $this->l('SQL injection historique'), 'description' => $this->l('Validation stricte des listes numeriques utilisees par les appels leoajax des branches anciennes.')],
                ['title' => $this->l('CVE-2024-6648'), 'description' => $this->l('Blocage de product_item_path fourni dans config et validation du chemin de template.')],
                ['title' => $this->l('ApGenCode / SSTI'), 'description' => $this->l('Controle des ecritures de templates et des primitives Smarty capables d ecrire ou executer du PHP.')],
                ['title' => $this->l('Journal securise'), 'description' => $this->l('Blocages traces dans un journal JSONL protege par garde PHP, sans table SQL et avec secrets masques.')],
            ],
            'actions_description' => $this->l('Les actions restent explicites et le scanner reste strictement borne a /modules/appagebuilder/.'),
            'actions' => [
                ['url' => $urls['logs'], 'title' => $this->l('Journal de securite'), 'description' => $this->l('IP, methode, URL, raison et payload filtre')],
                ['url' => $urls['scan'], 'title' => $this->l('Scanner AP Page Builder'), 'description' => '/modules/appagebuilder/ ' . $this->l('uniquement')],
                ['url' => $urls['maintenance'], 'title' => $this->l('Sauvegardes et restauration'), 'description' => $this->l('Rollback manuel des fichiers patches')],
                ['url' => $urls['information'], 'title' => $this->l('Sources et vulnerabilites'), 'description' => $this->l('CVE, Friends Of Presta, PrestaShop, INCIBE et LeoTheme')],
            ],
            'scope_message' => $this->l('Ce module est une mitigation pour AP Page Builder 2.2 a 2.4.9. La mise a jour officielle vers une version corrigee reste preferable des qu elle est compatible avec la boutique.'),
        ];
    }

    /**
     * Build security log data only when the Journal tab is displayed.
     *
     * @return array
     */
    private function buildLogsView()
    {
        $entries = PhApPageBuilderGuardCore::getRecentLogEntries(100);
        $info = PhApPageBuilderGuardCore::getLogInfo();
        $rows = [];

        foreach ($entries as $entry) {
            $event = isset($entry['event']) ? (string) $entry['event'] : '';
            $payload = isset($entry['payload']) ? json_encode($entry['payload'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '';
            if ($payload === false) {
                $payload = '';
            }
            $rows[] = [
                'date' => isset($entry['date']) ? $entry['date'] : '',
                'event' => $event,
                'tone' => strpos($event, 'blocked') === 0 ? 'is-danger' : ((strpos($event, 'rejected') !== false || strpos($event, 'obfuscation') !== false) ? 'is-warning' : 'is-neutral'),
                'ip' => isset($entry['ip']) ? $entry['ip'] : '',
                'forwarded_for_untrusted' => !empty($entry['forwarded_for_untrusted']) ? $entry['forwarded_for_untrusted'] : '',
                'method' => isset($entry['method']) ? $entry['method'] : '',
                'url' => isset($entry['url']) ? $entry['url'] : '',
                'reason' => isset($entry['reason']) ? $entry['reason'] : '',
                'payload' => $payload,
            ];
        }

        $info['formatted_bytes'] = $this->formatBytes($info['bytes']);

        return [
            'entries' => $rows,
            'count' => count($rows),
            'info' => $info,
            'description' => $this->l('Aucune table SQL : journal JSONL protege par garde PHP, rotation a 2 Mo et trois archives maximum. Seuls les parametres AP Page Builder utiles a l analyse sont conserves et les secrets connus sont masques avant ecriture.'),
            'clear_description' => $this->l('Supprime uniquement security.log et ses rotations. Aucun fichier AP Page Builder n est modifie.'),
            'empty_description' => $this->l('Les blocages et anomalies detectes par le guard apparaitront ici.'),
            'ip_description' => $this->l('Le champ IP utilise REMOTE_ADDR. Les en-tetes CF-Connecting-IP, X-Forwarded-For ou X-Real-IP sont conserves separement comme information non fiable, car ils peuvent etre usurpes sans configuration de proxy de confiance.'),
        ];
    }

    /**
     * Build scan data only when the Scanner tab is displayed.
     *
     * @param array|null $scan
     *
     * @return array
     */
    private function buildScanView($scan)
    {
        $rows = is_array($scan) ? $scan : [];

        return [
            'ran' => is_array($scan),
            'entries' => $rows,
            'result_title' => sprintf($this->l('%d alerte(s) detectee(s)'), count($rows)),
            'description' => $this->l('Analyse en lecture seule uniquement les fichiers situes sous /modules/appagebuilder/. Le scanner ne deplace, ne supprime et ne modifie aucun fichier. La racine PrestaShop, les themes et les autres modules sont volontairement exclus.'),
            'empty_description' => $this->l('Aucune signature a haute confiance n a ete trouvee dans le perimetre AP Page Builder.'),
        ];
    }

    /**
     * Build maintenance texts.
     *
     * @param array $status
     * @param int $enabled
     * @param array $manualBackup
     *
     * @return array
     */
    private function buildMaintenanceView(array $status, $enabled, array $manualBackup)
    {
        return [
            'runtime_description' => $this->l('La protection runtime est la couche de filtrage executee uniquement lorsque les points sensibles AP Page Builder patches sont appeles. Elle ne lance ni scan permanent ni cron en arriere-plan.'),
            'runtime_status' => $enabled ? $this->l('Active') : $this->l('Desactivee'),
            'runtime_items' => [
                [
                    'title' => $this->l('Requetes AJAX et parametres'),
                    'description' => $this->l('Controle le token leoajax quand la variante AP Page Builder le gere, cumule les controles galerie/config, valide les listes numeriques et ajoute un filet SQLi a haute confiance pour les anciens parametres inconnus.'),
                ],
                [
                    'title' => $this->l('Config Base64 et chemins'),
                    'description' => $this->l('Decode et valide la configuration AP Page Builder, refuse product_item_path fourni par la requete et bloque traversal, wrappers et chemins de template dangereux.'),
                ],
                [
                    'title' => $this->l('ApGenCode et ecritures de templates'),
                    'description' => $this->l('Controle les noms, chemins, extensions et contenus avant ecriture : seuls les formats AP Page Builder attendus sont admis et les scripts PHP/configurations serveur sont refuses.'),
                ],
                [
                    'title' => $this->l('Journalisation des blocages'),
                    'description' => $this->l('Chaque blocage du Guard est trace avec date, IP, methode, URL, motif et uniquement les parametres AP Page Builder utiles, filtres et bornes, sans base de donnees.'),
                ],
            ],
            'runtime_why' => $this->l('Pourquoi la laisser active ? Les fichiers AP Page Builder restent patches si vous desactivez cette option, mais les controles dynamiques appeles par le patch cessent alors de filtrer les requetes. La desactivation est surtout prevue pour un diagnostic temporaire en cas de doute ou de faux positif, puis la protection doit etre reactivee.'),
            'backup_description' => $this->l('Vous pouvez creer a tout moment une copie manuelle des fichiers AP Page Builder geres par le Guard. Elle est distincte du rollback cree automatiquement avant application du patch.'),
            'manual_backup_status' => $manualBackup['available'] ? $this->l('Sauvegarde manuelle disponible') : $this->l('Aucune sauvegarde manuelle'),
            'last_backup_label' => $this->l('Derniere sauvegarde :'),
            'rollback_description' => $this->l('Le Guard conserve automatiquement les fichiers originaux avant chaque modification. Ce rollback sert a retirer le patch en cas de probleme.'),
            'no_rollback' => $this->l('Aucun rollback pre-patch disponible pour le moment.'),
            'integrity_title' => $status['patched'] ? $this->l('Tous les correctifs attendus sont presents') : $this->l('Patch incomplet'),
            'integrity_description' => $this->l('Le statut est calcule a partir des marqueurs presents dans les fichiers cibles, pas uniquement a partir d une option en base de donnees.'),
            'integrity_status' => $status['patched'] ? $this->l('Conforme') : $this->l('Attention'),
            'important_message' => $this->l('Desactiver ou desinstaller ce module ne restaure pas automatiquement AP Page Builder. Pour retirer le patch, utilisez d abord la restauration manuelle puis videz le cache PrestaShop et Smarty.'),
        ];
    }

    /**
     * Build information, advisory and source data.
     *
     * @param array $apInfo
     * @param array $status
     *
     * @return array
     */
    private function buildInformationView(array $apInfo, array $status)
    {
        $version = $apInfo['version'] !== '' ? $apInfo['version'] : $this->l('inconnue');

        return [
            'version' => $version,
            'version_description' => $this->l('La version est lue depuis le code source du module, puis config.xml en secours. Le guard ne modifie jamais artificiellement le numero de version AP Page Builder.'),
            'support_status' => $apInfo['supported'] ? $this->l('Supportee') : $this->l('Hors perimetre'),
            'items' => [
                ['label' => $this->l('Version'), 'value' => $version],
                ['label' => $this->l('Source de detection'), 'value' => $apInfo['source'] !== '' ? $apInfo['source'] : '-'],
                ['label' => $this->l('Branche cible'), 'value' => '2.2.0 → 2.4.9'],
                ['label' => $this->l('Token leoajax dans cette variante'), 'value' => $apInfo['ajax_token'] ? $this->l('Oui') : $this->l('Non detecte')],
                ['label' => 'ApGenCode', 'value' => $apInfo['apgencode'] ? $this->l('Present') : $this->l('Non detecte')],
                ['label' => $this->l('Patch Guard'), 'value' => $status['patched'] ? $this->l('Actif') : $this->l('Incomplet')],
            ],
            'compatibility_description' => $this->l('Le patch s adapte au code detecte au lieu de supposer que toutes les versions 2.x ont exactement les memes lignes.'),
            'compatibility' => [
                ['range' => '2.2.0 - 2.4.5', 'description' => $this->l('SQLi historiques + traversal + ApGenCode/SSTI + journal')],
                ['range' => '2.4.6 - 2.4.9', 'description' => $this->l('Traversal + ApGenCode/SSTI + journal + validation AJAX adaptee au code present')],
                ['range' => '>= 4.0.0', 'description' => $this->l('Hors perimetre : utiliser la version officielle corrigee')],
            ],
            'tested_archives' => '2.4.1, 2.4.3, 2.4.5, 2.4.8. ' . $this->l('Les autres versions de la plage sont supportees par detection structurelle : si un point d insertion attendu n est pas reconnu, le patch abandonne plutot que de modifier le fichier au hasard.'),
            'advisory_description' => $this->l('Les protections ci-dessous reposent en priorite sur les avis de securite publics et les publications de l editeur.'),
            'advisories' => $this->buildAdvisoriesView(),
            'sources' => $this->buildSourcesView(),
            'community_message' => $this->l('Les forums et retours communautaires sont utiles pour reperer des incidents, mais aucun correctif automatique n est integre uniquement sur cette base. Les modifications du Guard sont recoupees avec le code installe et des avis techniques publics.'),
            'limits_message' => $this->l('Le scanner integre ne sort jamais de /modules/appagebuilder/. Il ne trouvera donc pas un ancien dropper deja depose dans /themes/.../modules/appagebuilder/ ou a la racine. Apres une compromission, un audit malware global et une verification des comptes/acces restent necessaires.'),
        ];
    }

    /**
     * Build the vulnerability cards displayed in the Information tab.
     *
     * @return array
     */
    private function buildAdvisoriesView()
    {
        return [
            [
                'title' => 'CVE-2022-22897',
                'type' => $this->l('SQL injections non authentifiees'),
                'affected' => $this->l('AP Page Builder <= 2.4.5 selon Friends Of Presta'),
                'severity' => $this->l('Critique 9.8'),
                'description' => $this->l('Les parametres historiques incluent notamment product_all_one_img, image_product et plusieurs listes utilisees par leoajax. Les correctifs sont adaptes a la structure de chaque archive detectee.'),
                'url' => 'https://security.friendsofpresta.org/modules/2023/01/05/appagebuilder.html',
                'source' => 'Friends Of Presta',
            ],
            [
                'title' => 'CVE-2022-44897',
                'type' => $this->l('Cross-Site Scripting via show_number'),
                'affected' => $this->l('AP Page Builder <= 2.4.4 selon NVD'),
                'severity' => $this->l('Moyenne 6.1'),
                'description' => $this->l('Le parametre show_number peut recevoir un contenu HTML/JavaScript malveillant sur les branches concernees. Le Guard impose une valeur numerique bornee avant retour au code historique.'),
                'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2022-44897',
                'source' => 'NVD',
            ],
            [
                'title' => 'CVE-2023-3743',
                'type' => $this->l('SQL injection via product_one_img'),
                'affected' => $this->l('Numerotation de versions incoherente dans le record officiel'),
                'severity' => $this->l('Haute 7.5'),
                'description' => $this->l('Le record NVD/INCIBE vise product_one_img mais publie une plage de versions ne correspondant pas aux numeros 2.x du module. Le Guard protege donc ce parametre sur toute la branche 2.2 a 2.4.9 sans inferer une correspondance de version.'),
                'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2023-3743',
                'source' => 'NVD',
            ],
            [
                'title' => 'CVE-2024-6648',
                'type' => $this->l('Absolute Path Traversal'),
                'affected' => $this->l('Toutes versions < 4.0.0'),
                'severity' => $this->l('Haute 8.7'),
                'description' => $this->l('Un utilisateur distant non authentifie peut modifier product_item_path dans le JSON config encode en Base64 afin de lire des fichiers du systeme. Friends Of Presta signale aussi les variantes Base64 obfusquees.'),
                'url' => 'https://security.friendsofpresta.org/modules/2025/05/22/appagebuilder.html',
                'source' => 'Friends Of Presta',
            ],
            [
                'title' => $this->l('Alerte LeoTheme 2026'),
                'type' => $this->l('ApGenCode : SSTI / Arbitrary File Write / RCE'),
                'affected' => $this->l('Correctif editeur publie en 2026'),
                'severity' => $this->l('Critique selon editeur'),
                'description' => $this->l('LeoTheme a publie une alerte specifique sur ApGenCode. Le Guard controle les noms de fichiers, les chemins et les primitives Smarty dangereuses avant toute generation de template.'),
                'url' => 'https://blog.leotheme.com/fix-critical-unauthenticated-rce-via-apgencode-server-side-template-injection-arbitrary-file-write.html',
                'source' => 'LeoTheme',
            ],
        ];
    }

    /**
     * Build official references displayed in the Information tab.
     *
     * @return array
     */
    private function buildSourcesView()
    {
        return [
            ['label' => 'LeoTheme - centre AP Page Builder', 'url' => 'https://blog.leotheme.com/prestashop-module-tutorials/ap-page-builder'],
            ['label' => 'LeoTheme - correctif RCE ApGenCode 2026', 'url' => 'https://blog.leotheme.com/fix-critical-unauthenticated-rce-via-apgencode-server-side-template-injection-arbitrary-file-write.html'],
            ['label' => 'LeoTheme - correctif SSTI / Path Traversal 2026', 'url' => 'https://blog.leotheme.com/fix-vulnerable-to-the-same-server-side-template-injection-path-traversal.html'],
            ['label' => 'LeoTheme - avis SQLi AP PageBuilder 2.2.4', 'url' => 'https://blog.leotheme.com/security-issue-with-the-module-appagebuilder-v-2-2-4.html'],
            ['label' => 'Friends Of Presta - CVE-2022-22897', 'url' => 'https://security.friendsofpresta.org/modules/2023/01/05/appagebuilder.html'],
            ['label' => 'NVD - CVE-2022-22897', 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2022-22897'],
            ['label' => 'NVD - CVE-2022-44897', 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2022-44897'],
            ['label' => 'NVD - CVE-2023-3743', 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2023-3743'],
            ['label' => 'Friends Of Presta - CVE-2024-6648', 'url' => 'https://security.friendsofpresta.org/modules/2025/05/22/appagebuilder.html'],
            ['label' => 'NVD - CVE-2024-6648', 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2024-6648'],
            ['label' => 'PrestaShop Help Center - mise en conformite AP Page Builder', 'url' => 'https://help-center.prestashop.com/hc/fr/articles/25492821315346-Mise-en-conformit%C3%A9-du-module-Ap-Page-Builder'],
        ];
    }

    /**
     * Format a byte count for the back-office.
     *
     * @param int $bytes
     *
     * @return string
     */
    private function formatBytes($bytes)
    {
        $bytes = (int) $bytes;
        if ($bytes >= 1048576) {
            return number_format($bytes / 1048576, 2, ',', ' ') . ' Mo';
        }
        if ($bytes >= 1024) {
            return number_format($bytes / 1024, 1, ',', ' ') . ' Ko';
        }

        return $bytes . ' o';
    }

    private function ensureWritableDirs()
    {
        $storageDir = $this->getBackupDir();
        if (!is_dir($storageDir) && !@mkdir($storageDir, 0750, true)) {
            return false;
        }
        @chmod($storageDir, 0750);
        $this->protectStorageDir($storageDir);

        return true;
    }

    private function getApPageBuilderInfo()
    {
        if (is_array($this->apPageBuilderInfoCache)) {
            return $this->apPageBuilderInfoCache;
        }

        $root = _PS_MODULE_DIR_ . 'appagebuilder/';
        $info = [
            'installed' => is_dir($root),
            'version' => '',
            'source' => '',
            'supported' => false,
            'ajax_token' => false,
            'apgencode' => false,
        ];

        if (!$info['installed']) {
            $this->apPageBuilderInfoCache = $info;

            return $info;
        }

        $main = $root . 'appagebuilder.php';
        if (is_file($main) && is_readable($main)) {
            $content = Tools::file_get_contents($main);
            if (preg_match('/\\$this->version\\s*=\\s*[\\\'\"]([0-9]+(?:\\.[0-9]+){1,3})[\\\'\"]\\s*;/', $content, $m)) {
                $info['version'] = $m[1];
                $info['source'] = 'appagebuilder.php';
            }
        }

        if ($info['version'] === '') {
            $config = $root . 'config.xml';
            if (is_file($config) && is_readable($config)) {
                $xml = Tools::file_get_contents($config);
                if (preg_match('#<version>\\s*(?:<!\\[CDATA\\[)?\\s*([0-9]+(?:\\.[0-9]+){1,3})#i', $xml, $m)) {
                    $info['version'] = $m[1];
                    $info['source'] = 'config.xml';
                }
            }
        }

        if ($info['version'] === '') {
            $module = Module::getInstanceByName('appagebuilder');
            if ($module) {
                $info['version'] = (string) $module->version;
                $info['source'] = 'Module::getInstanceByName';
            }
        }

        if ($info['version'] !== '') {
            $info['supported'] = version_compare($info['version'], '2.2.0', '>=') && version_compare($info['version'], '2.4.9', '<=');
        }

        $ajax = $root . 'apajax.php';
        if (is_file($ajax) && is_readable($ajax)) {
            $content = Tools::file_get_contents($ajax);
            $info['ajax_token'] = $this->sourceHasAjaxTokenCheck($content);
        }

        $gen = $root . 'classes/shortcodes/ApGenCode.php';
        if (is_file($gen) && is_readable($gen)) {
            $info['apgencode'] = true;
        }

        $this->apPageBuilderInfoCache = $info;

        return $info;
    }

    private function sourceHasAjaxTokenCheck($content)
    {
        return (bool) preg_match('/Tools::getToken\\s*\\(\\s*false\\s*\\)[^\\n]{0,180}Tools::getValue\\s*\\(\\s*[\\\'\"]token[\\\'\"]\\s*\\)|Tools::getValue\\s*\\(\\s*[\\\'\"]token[\\\'\"]\\s*\\)[^\\n]{0,180}Tools::getToken\\s*\\(\\s*false\\s*\\)/i', (string) $content);
    }

    private function protectStorageDir($dir)
    {
        $htaccess = rtrim($dir, '/\\') . '/.htaccess';
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            @chmod($htaccess, 0600);
        }
        $index = rtrim($dir, '/\\') . '/index.php';
        if (!is_file($index)) {
            @file_put_contents($index, "<?php\nexit;\n");
            @chmod($index, 0600);
        }
    }

    private function getPatchStatus()
    {
        $definitions = $this->getPatchDefinitions();
        $details = [];
        $patched = true;

        foreach ($definitions as $definition) {
            $file = $definition['file'];
            $label = $definition['label'];
            $required = !empty($definition['required']);
            $markers = $definition['markers'];

            if (!is_file($file)) {
                $details[] = $label . ' : ' . ($required ? 'absent' : 'non applicable');
                if ($required) {
                    $patched = false;
                }
                continue;
            }

            $content = Tools::file_get_contents($file);
            $ok = true;
            foreach ($markers as $marker) {
                if (strpos($content, $marker) === false) {
                    $ok = false;

                    break;
                }
            }

            $details[] = $label . ' : ' . ($ok ? 'patche' : 'non patche ou incomplet');
            if (!$ok && $required) {
                $patched = false;
            }
        }

        return ['patched' => $patched, 'details' => $details];
    }

    /**
     * Construit la liste des fichiers et marqueurs attendus pour la variante
     * installee en ne lisant chaque fichier optionnel qu une seule fois.
     *
     * @return array
     */
    private function getPatchDefinitions()
    {
        $root = _PS_MODULE_DIR_ . 'appagebuilder/';
        $definitions = [
            [
                'file' => $root . 'apajax.php',
                'label' => 'apajax.php',
                'required' => true,
                'markers' => [self::PATCH_MARKER . '_APAJAX_START', self::PATCH_MARKER . '_APAJAX_END'],
            ],
            [
                'file' => $root . 'classes/shortcodes/ApProductList.php',
                'label' => 'ApProductList.php',
                'required' => true,
                'markers' => [
                    self::PATCH_MARKER . '_PRODUCTLIST_INPUT_START',
                    self::PATCH_MARKER . '_PRODUCTLIST_INPUT_END',
                    self::PATCH_MARKER . '_PRODUCTLIST_STORAGE_START',
                    self::PATCH_MARKER . '_PRODUCTLIST_STORAGE_END',
                    self::PATCH_MARKER . '_PRODUCTLIST_PATH_START',
                    self::PATCH_MARKER . '_PRODUCTLIST_PATH_END',
                ],
            ],
        ];

        $setting = $root . 'classes/ApPageSetting.php';
        if (is_file($setting)) {
            $definitions[] = [
                'file' => $setting,
                'label' => 'ApPageSetting.php',
                'required' => true,
                'markers' => [self::PATCH_MARKER . '_WRITEFILE_START', self::PATCH_MARKER . '_WRITEFILE_END'],
            ];
        }

        $gen = $root . 'classes/shortcodes/ApGenCode.php';
        $genContent = $this->readOptionalFile($gen);
        if ($genContent !== '' && (
            (
                strpos($genContent, 'content_html') !== false
                && strpos($genContent, 'ApPageSetting::writeFile') !== false
            )
            || strpos($genContent, self::PATCH_MARKER . '_APGENCODE_START') !== false
        )) {
            $definitions[] = [
                'file' => $gen,
                'label' => 'ApGenCode.php',
                'required' => true,
                'markers' => [self::PATCH_MARKER . '_APGENCODE_START', self::PATCH_MARKER . '_APGENCODE_END'],
            ];
        }

        $remote = $root . 'controllers/admin/AdminApPageBuilderThemeConfiguration.php';
        $remoteContent = $this->readOptionalFile($remote);
        if ($remoteContent !== '' && (
            strpos($remoteContent, self::PATCH_MARKER . '_BREADCRUMB_START') !== false
            || (
                strpos($remoteContent, 'updateBreadcrumb') !== false
                && preg_match('#http://leothe[^\\n]{0,40}me\\.com/updatemodule/appagebuilder/#i', $remoteContent)
            )
        )) {
            $definitions[] = [
                'file' => $remote,
                'label' => 'AdminApPageBuilderThemeConfiguration.php',
                'required' => true,
                'markers' => [self::PATCH_MARKER . '_BREADCRUMB_START', self::PATCH_MARKER . '_BREADCRUMB_END'],
            ];
        }

        return $definitions;
    }

    /**
     * Lit un fichier optionnel sans lever d exception.
     *
     * @param string $file
     *
     * @return string
     */
    private function readOptionalFile($file)
    {
        if (!is_file($file) || !is_readable($file)) {
            return '';
        }

        $content = Tools::file_get_contents($file);

        return is_string($content) ? $content : '';
    }

    private function applyPatch()
    {
        $info = $this->getApPageBuilderInfo();
        if (!$info['installed']) {
            throw new Exception('AP Page Builder / appagebuilder n est pas installe.');
        }
        if (!$info['supported']) {
            throw new Exception('Version AP Page Builder hors perimetre automatique : ' . ($info['version'] !== '' ? $info['version'] : 'inconnue') . '. Versions supportees : 2.2.0 a 2.4.9.');
        }

        $status = $this->getPatchStatus();
        if ($status['patched']) {
            return ['Le patch defensif est deja completement applique. Aucune modification effectuee.'];
        }

        $messages = [];
        $this->patchApAjax($messages);
        $this->patchApPageSetting($messages);
        $this->patchApProductList($messages);
        $this->patchApGenCode($messages);
        $this->patchRemoteBreadcrumb($messages);

        $status = $this->getPatchStatus();
        if (!$status['patched']) {
            $messages[] = 'Attention : le patch reste incomplet. Verifiez l onglet Maintenance avant mise en production.';
        }
        return $messages;
    }

    private function patchApAjax(array &$messages)
    {
        $file = _PS_MODULE_DIR_ . 'appagebuilder/apajax.php';
        $content = $this->readTarget($file);
        if (strpos($content, self::PATCH_MARKER . '_APAJAX_START') !== false
            && strpos($content, self::PATCH_MARKER . '_APAJAX_END') !== false) {
            $messages[] = 'apajax.php deja patche.';

            return;
        }

        $tokenRequired = $this->sourceHasAjaxTokenCheck($content) ? 'true' : 'false';
        $guard = '/* ' . self::PATCH_MARKER . "_APAJAX_START */\n"
            . "if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
            . "    require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
            . '    PhApPageBuilderGuardCore::guardApAjax(' . $tokenRequired . ");\n"
            . "}\n"
            . '/* ' . self::PATCH_MARKER . "_APAJAX_END */\n\n";

        if (!preg_match('/^[ \\t]*if\\s*\\(\\s*Tools::getValue\\s*\\(/m', $content, $match, PREG_OFFSET_CAPTURE)) {
            throw new Exception('Point insertion apajax.php introuvable. Patch abandonne.');
        }

        $offset = $match[0][1];
        $content = substr($content, 0, $offset) . $guard . substr($content, $offset);
        $this->writeTarget($file, $content);
        $messages[] = 'apajax.php patche : controles AJAX adaptes a cette variante (token=' . $tokenRequired . ').';
    }

    private function patchApPageSetting(array &$messages)
    {
        $file = _PS_MODULE_DIR_ . 'appagebuilder/classes/ApPageSetting.php';
        if (!is_file($file)) {
            $messages[] = 'ApPageSetting.php absent : controle central non applicable.';

            return;
        }
        $content = $this->readTarget($file);
        if (strpos($content, self::PATCH_MARKER . '_WRITEFILE_START') !== false
            && strpos($content, self::PATCH_MARKER . '_WRITEFILE_END') !== false) {
            $messages[] = 'ApPageSetting.php deja patche.';

            return;
        }

        $pattern = '/^([ \\t]*)\\$file\\s*=\\s*\\$folder\\s*\\.\\s*[\\\'\"]\\/[\\\'\"]\\s*\\.\\s*\\$file\\s*;[ \\t]*$/m';
        $new = preg_replace_callback($pattern, function ($m) {
            $i = $m[1];

            return $m[0] . "\n"
                . $i . '/* ' . self::PATCH_MARKER . "_WRITEFILE_START */\n"
                . $i . "if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
                . $i . "    require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
                . $i . '    PhApPageBuilderGuardCore::guardWriteFile($file, $value);' . "\n"
                . $i . "}\n"
                . $i . '/* ' . self::PATCH_MARKER . '_WRITEFILE_END */';
        }, $content, 1, $count);

        if ($count !== 1) {
            throw new Exception('Point insertion ApPageSetting::writeFile introuvable.');
        }
        $this->writeTarget($file, $new);
        $messages[] = 'ApPageSetting.php patche : controle central des ecritures et templates Smarty.';
    }

    private function patchApProductList(array &$messages)
    {
        $file = _PS_MODULE_DIR_ . 'appagebuilder/classes/shortcodes/ApProductList.php';
        $content = $this->readTarget($file);
        $changed = false;

        if (strpos($content, self::PATCH_MARKER . '_PRODUCTLIST_INPUT_START') === false) {
            $patternInput = '/^([ \\t]*)(\\$input\\s*=\\s*(?:Tools::jsonDecode|json_decode)\\s*\\([^;\\n]*Tools::getValue\\s*\\(\\s*[\\\'\"]config[\\\'\"]\\s*\\)[^;\\n]*\\)\\s*;)[ \\t]*$/m';
            $new = preg_replace_callback($patternInput, function ($m) {
                $i = $m[1];

                return $m[0] . "\n"
                    . $i . '/* ' . self::PATCH_MARKER . "_PRODUCTLIST_INPUT_START */\n"
                    . $i . "if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
                    . $i . "    require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
                    . $i . '    $input = PhApPageBuilderGuardCore::sanitizeApProductListInput($input);' . "\n"
                    . $i . "}\n"
                    . $i . '/* ' . self::PATCH_MARKER . '_PRODUCTLIST_INPUT_END */';
            }, $content, 1, $countInput);
            if ($countInput !== 1) {
                throw new Exception('Point insertion config/Base64 ApProductList introuvable.');
            }
            $content = $new;
            $changed = true;
        }

        // Stockage du chemin : convertit aussi la variante vulnerable documentee
        // par PrestaShop en cookie serveur. Ce marqueur est obligatoire : son absence
        // maintient le statut en Patch incomplet et fait echouer le patch en mode fail-safe.
        if (strpos($content, self::PATCH_MARKER . '_PRODUCTLIST_STORAGE_START') === false) {
            $storagePattern = '/^([ \\t]*)(?!\\/\\/)\\$apPConfig\\[[\\\'\"]product_item_path[\\\'\"]\\]\\s*=\\s*\\$assign\\[[\\\'\"]product_item_path[\\\'\"]\\]\\s*;[ \\t]*$/m';
            $storageReplacement = '$1/* ' . self::PATCH_MARKER . "_PRODUCTLIST_STORAGE_START */\n"
                . '$1Context::getContext()->cookie->{\'productItemPathApProductList_\'.$assign[\'formAtts\'][\'form_id\']} = $assign[\'product_item_path\'];' . "\n"
                . '$1/* ' . self::PATCH_MARKER . '_PRODUCTLIST_STORAGE_END */';
            $content2 = preg_replace($storagePattern, $storageReplacement, $content, 1, $countStorage);
            if ($countStorage === 1) {
                $content = $content2;
                $changed = true;
            } else {
                $cookiePattern = '/^([ \\t]*)(Context::getContext\\(\\)->cookie->\\{[\\\'\"]productItemPathApProductList_[\\\'\"]\\.\\$assign\\[[\\\'\"]formAtts[\\\'\"]\\]\\[[\\\'\"]form_id[\\\'\"]\\]\\}\\s*=\\s*\\$assign\\[[\\\'\"]product_item_path[\\\'\"]\\]\\s*;)[ \\t]*$/m';
                $content2 = preg_replace($cookiePattern, '$1/* ' . self::PATCH_MARKER . "_PRODUCTLIST_STORAGE_START */\n" . '$1$2' . "\n" . '$1/* ' . self::PATCH_MARKER . '_PRODUCTLIST_STORAGE_END */', $content, 1, $countCookie);
                if ($countCookie === 1) {
                    $content = $content2;
                    $changed = true;
                } else {
                    throw new Exception('Stockage product_item_path introuvable dans ApProductList.php. Patch abandonne.');
                }
            }
        }

        if (strpos($content, self::PATCH_MARKER . '_PRODUCTLIST_PATH_START') === false) {
            $pathPattern = '/^([ \\t]*)\\$assign\\[[\\\'\"]product_item_path[\\\'\"]\\]\\s*=\\s*(?:\\$input->product_item_path|Context::getContext\\(\\)->cookie->\\{[^;\\n]+)\\s*;[ \\t]*$/m';
            $new = preg_replace_callback($pathPattern, function ($m) {
                $i = $m[1];

                return $i . '/* ' . self::PATCH_MARKER . "_PRODUCTLIST_PATH_START */\n"
                    . $i . "if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
                    . $i . "    require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
                    . $i . '    $assign[\'product_item_path\'] = PhApPageBuilderGuardCore::getSafeProductItemPath(isset($input->form_id) ? $input->form_id : \'\');' . "\n"
                    . $i . "} else {\n"
                    . $i . '    $assign[\'product_item_path\'] = Context::getContext()->cookie->{\'productItemPathApProductList_\'.$input->form_id};' . "\n"
                    . $i . "}\n"
                    . $i . '/* ' . self::PATCH_MARKER . '_PRODUCTLIST_PATH_END */';
            }, $content, 1, $countPath);
            if ($countPath !== 1) {
                throw new Exception('Lecture product_item_path introuvable dans ApProductList.php.');
            }
            $content = $new;
            $changed = true;
        }

        if (!$changed) {
            $messages[] = 'ApProductList.php deja patche.';

            return;
        }
        $this->writeTarget($file, $content);
        $messages[] = 'ApProductList.php patche : Base64/config nettoyes et product_item_path borne.';
    }

    private function patchApGenCode(array &$messages)
    {
        $file = _PS_MODULE_DIR_ . 'appagebuilder/classes/shortcodes/ApGenCode.php';
        if (!is_file($file)) {
            $messages[] = 'ApGenCode.php absent : protection SSTI directe non applicable.';

            return;
        }
        $content = $this->readTarget($file);
        if (strpos($content, self::PATCH_MARKER . '_APGENCODE_START') !== false
            && strpos($content, self::PATCH_MARKER . '_APGENCODE_END') !== false) {
            $messages[] = 'ApGenCode.php deja patche.';

            return;
        }
        if (strpos($content, 'content_html') === false || strpos($content, 'ApPageSetting::writeFile') === false) {
            $messages[] = 'ApGenCode.php present mais motif historique content_html/writeFile non detecte : aucune modification.';

            return;
        }

        $pattern = '/^([ \\t]*)(\\$value\\s*=\\s*isset\\s*\\(\\s*\\$assign\\[[\\\'\"]formAtts[\\\'\"]\\]\\[[\\\'\"]content_html[\\\'\"]\\]\\s*\\)[^;\\n]*;)[ \\t]*$/m';
        $new = preg_replace_callback($pattern, function ($m) {
            $i = $m[1];

            return $m[0] . "\n"
                . $i . '/* ' . self::PATCH_MARKER . "_APGENCODE_START */\n"
                . $i . "if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
                . $i . "    require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
                . $i . '    PhApPageBuilderGuardCore::guardGeneratedTemplate($folder, $file, $value);' . "\n"
                . $i . "}\n"
                . $i . '/* ' . self::PATCH_MARKER . '_APGENCODE_END */';
        }, $content, 1, $count);
        if ($count !== 1) {
            throw new Exception('Point insertion ApGenCode::generateFile introuvable.');
        }
        $this->writeTarget($file, $new);
        $messages[] = 'ApGenCode.php patche : controle SSTI/chemin avant generation du template.';
    }

    private function patchRemoteBreadcrumb(array &$messages)
    {
        $file = _PS_MODULE_DIR_ . 'appagebuilder/controllers/admin/AdminApPageBuilderThemeConfiguration.php';
        if (!is_file($file)) {
            $messages[] = 'updateBreadcrumb absent : hardening HTTP distant non applicable.';

            return;
        }
        $content = $this->readTarget($file);
        if (strpos($content, self::PATCH_MARKER . '_BREADCRUMB_START') !== false) {
            $messages[] = 'AdminApPageBuilderThemeConfiguration.php deja patche.';

            return;
        }
        if (strpos($content, 'updateBreadcrumb') === false
            || !preg_match('#http://leothe[^\\n]{0,40}me\\.com/updatemodule/appagebuilder/#i', $content)) {
            $messages[] = 'Aucun telechargement HTTP historique updateBreadcrumb detecte.';

            return;
        }

        if (!preg_match('/public\\s+function\\s+updateBreadcrumb\\s*\\([^)]*\\)\\s*\\{/', $content, $m, PREG_OFFSET_CAPTURE)) {
            throw new Exception('Fonction updateBreadcrumb non reconnue.');
        }
        $start = $m[0][1];
        $open = strpos($content, '{', $start);
        if ($open === false) {
            throw new Exception('Bloc updateBreadcrumb introuvable.');
        }
        $depth = 0;
        $end = false;
        $len = strlen($content);
        for ($i = $open; $i < $len; ++$i) {
            if ($content[$i] === '{') {
                ++$depth;
            } elseif ($content[$i] === '}') {
                --$depth;
                if ($depth === 0) {
                    $end = $i;

                    break;
                }
            }
        }
        if ($end === false) {
            throw new Exception('Fin updateBreadcrumb introuvable.');
        }

        $replacement = "public function updateBreadcrumb()\n"
            . "    {\n"
            . '        /* ' . self::PATCH_MARKER . "_BREADCRUMB_START */\n"
            . "        if (defined('_PS_MODULE_DIR_') && file_exists(_PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php')) {\n"
            . "            require_once _PS_MODULE_DIR_.'phappagebuilderguard/classes/PhApPageBuilderGuard.php';\n"
            . "            PhApPageBuilderGuardCore::logEvent('remote_http_update_blocked', 'updateBreadcrumb HTTP non verifie desactive');\n"
            . "        }\n"
            . '        $this->errors[] = $this->l(\'Remote HTTP update disabled by Phenix AP PageBuilder Guard.\');' . "\n"
            . "        return false;\n"
            . '        /* ' . self::PATCH_MARKER . "_BREADCRUMB_END */\n"
            . '    }';
        $new = substr($content, 0, $start) . $replacement . substr($content, $end + 1);
        $this->writeTarget($file, $new);
        $messages[] = 'AdminApPageBuilderThemeConfiguration.php patche : telechargement HTTP distant non verifie desactive.';
    }

    private function readTarget($file)
    {
        if (!is_file($file)) {
            throw new Exception('Fichier introuvable : ' . $file);
        }
        if (!is_readable($file) || !is_writable($file)) {
            throw new Exception('Fichier non lisible ou non modifiable : ' . $file);
        }

        $content = Tools::file_get_contents($file);
        if (!is_string($content)) {
            throw new Exception('Lecture impossible : ' . $file);
        }

        return $content;
    }

    /**
     * Remplace un fichier de facon atomique apres creation du backup.
     * Le fichier temporaire est cree dans le meme repertoire afin que rename()
     * reste sur le meme systeme de fichiers.
     *
     * @param string $file
     * @param string $content
     *
     * @throws Exception
     */
    private function writeTarget($file, $content)
    {
        $this->backupFile($file);

        $directory = dirname($file);
        $temporary = tempnam($directory, '.phapb-');
        if ($temporary === false) {
            throw new Exception('Impossible de creer un fichier temporaire pour : ' . $file);
        }

        $mode = @fileperms($file);
        $written = file_put_contents($temporary, $content, LOCK_EX);
        if ($written === false || $written !== strlen($content)) {
            @unlink($temporary);

            throw new Exception('Impossible d ecrire le fichier temporaire pour : ' . $file);
        }

        if ($mode !== false) {
            @chmod($temporary, $mode & 0777);
        }

        if (!@rename($temporary, $file)) {
            @unlink($temporary);

            throw new Exception('Impossible de remplacer atomiquement : ' . $file);
        }

        $this->apPageBuilderInfoCache = null;
    }

    /**
     * Restaure une copie par remplacement atomique afin d eviter une cible
     * partiellement ecrite si le disque ou le processus echoue en cours de copie.
     *
     * @param string $source
     * @param string $target
     *
     * @throws Exception
     */
    private function replaceFileFromSource($source, $target)
    {
        if (!is_file($source) || !is_readable($source)) {
            throw new Exception('Source de restauration introuvable : ' . $source);
        }

        $temporary = tempnam(dirname($target), '.phapb-restore-');
        if ($temporary === false) {
            throw new Exception('Impossible de creer le fichier temporaire de restauration.');
        }

        if (!copy($source, $temporary)) {
            @unlink($temporary);

            throw new Exception('Impossible de preparer la restauration de : ' . $target);
        }

        $mode = @fileperms($target);
        if ($mode !== false) {
            @chmod($temporary, $mode & 0777);
        }

        if (!@rename($temporary, $target)) {
            @unlink($temporary);

            throw new Exception('Impossible de remplacer la cible : ' . $target);
        }

        $this->apPageBuilderInfoCache = null;
    }

    private function backupFile($file, $kind = 'bak')
    {
        $dir = $this->getBackupDir();
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new Exception('Repertoire de sauvegarde impossible a creer : ' . $dir);
        }

        $this->protectStorageDir($dir);
        $relative = str_replace([_PS_ROOT_DIR_, '\\', '/'], ['', '_', '_'], $file);
        $kind = ($kind === 'rollback') ? 'rollback' : 'bak';
        $base = $dir . '/' . date('Ymd-His') . '-' . substr(sha1($file), 0, 10) . $relative;
        $backup = $base . '.' . $kind;
        $suffix = 0;
        while (file_exists($backup)) {
            ++$suffix;
            $backup = $base . '-' . $suffix . '.' . $kind;
        }
        if (!copy($file, $backup)) {
            throw new Exception('Sauvegarde impossible : ' . $backup);
        }
        @chmod($backup, 0600);
    }

    private function getPatchTargets()
    {
        return [
            _PS_MODULE_DIR_ . 'appagebuilder/apajax.php' => 'apajax.php',
            _PS_MODULE_DIR_ . 'appagebuilder/classes/ApPageSetting.php' => 'ApPageSetting.php',
            _PS_MODULE_DIR_ . 'appagebuilder/classes/shortcodes/ApProductList.php' => 'ApProductList.php',
            _PS_MODULE_DIR_ . 'appagebuilder/classes/shortcodes/ApGenCode.php' => 'ApGenCode.php',
            _PS_MODULE_DIR_ . 'appagebuilder/controllers/admin/AdminApPageBuilderThemeConfiguration.php' => 'AdminApPageBuilderThemeConfiguration.php',
        ];
    }

    private function getBackupDir()
    {
        return rtrim(_PS_ROOT_DIR_, '/\\') . '/var/phappagebuilderguard/backups';
    }

    private function getLegacyBackupDir()
    {
        return dirname(__FILE__) . '/backups';
    }

    private function hasAnyBackup()
    {
        foreach (array_keys($this->getPatchTargets()) as $file) {
            if ($this->findLatestBackupForFile($file) !== '') {
                return true;
            }
        }

        return false;
    }

    private function findLatestBackupForFile($file)
    {
        $relative = str_replace([_PS_ROOT_DIR_, '\\', '/'], ['', '_', '_'], $file);
        $pattern = '*-' . substr(sha1($file), 0, 10) . $relative . '.bak';
        $candidates = [];

        foreach ([$this->getBackupDir(), $this->getLegacyBackupDir()] as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            foreach ((array) glob($dir . '/' . $pattern) as $backup) {
                if (is_file($backup) && is_readable($backup)) {
                    $candidates[] = $backup;
                }
            }
        }

        if (!$candidates) {
            return '';
        }

        usort($candidates, function ($a, $b) {
            return filemtime($b) - filemtime($a);
        });

        return $candidates[0];
    }

    private function getManualBackupRoot()
    {
        return $this->getBackupDir() . '/manual';
    }

    private function getLatestManualBackupInfo()
    {
        $root = $this->getManualBackupRoot();
        $result = ['available' => false, 'dir' => '', 'date' => '', 'files' => 0];
        if (!is_dir($root)) {
            return $result;
        }

        $dirs = [];
        foreach ((array) glob($root . '/*', GLOB_ONLYDIR) as $dir) {
            if (is_file($dir . '/manifest.json')) {
                $dirs[] = $dir;
            }
        }
        if (!$dirs) {
            return $result;
        }

        usort($dirs, function ($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        $dir = $dirs[0];
        $manifest = json_decode((string) @file_get_contents($dir . '/manifest.json'), true);
        if (!is_array($manifest) || empty($manifest['files']) || !is_array($manifest['files'])) {
            return $result;
        }

        $result['available'] = true;
        $result['dir'] = $dir;
        $result['date'] = !empty($manifest['date']) ? (string) $manifest['date'] : date('c', filemtime($dir));
        $result['files'] = count($manifest['files']);

        return $result;
    }

    private function createManualBackup()
    {
        $root = $this->getManualBackupRoot();
        if (!is_dir($root) && !@mkdir($root, 0750, true)) {
            throw new Exception('Impossible de creer le repertoire de sauvegarde manuelle : ' . $root);
        }
        @chmod($root, 0750);
        $this->protectStorageDir($root);

        $stamp = date('Ymd-His');
        $dir = $root . '/' . $stamp;
        $suffix = 0;
        while (file_exists($dir)) {
            ++$suffix;
            $dir = $root . '/' . $stamp . '-' . $suffix;
        }
        if (!@mkdir($dir, 0750, true)) {
            throw new Exception('Impossible de creer le snapshot : ' . $dir);
        }
        @chmod($dir, 0750);
        $this->protectStorageDir($dir);

        $manifest = [
            'date' => date('c'),
            'guard_version' => $this->version,
            'appagebuilder_version' => $this->getApPageBuilderInfo()['version'],
            'files' => [],
        ];

        foreach ($this->getPatchTargets() as $file => $label) {
            if (!is_file($file) || !is_readable($file)) {
                continue;
            }
            $relative = ltrim(str_replace('\\', '/', str_replace(_PS_ROOT_DIR_, '', $file)), '/');
            if (strpos($relative, 'modules/appagebuilder/') !== 0) {
                throw new Exception('Chemin de sauvegarde refuse : ' . $relative);
            }
            $destination = $dir . '/files/' . $relative;
            $destinationDir = dirname($destination);
            if (!is_dir($destinationDir) && !@mkdir($destinationDir, 0750, true)) {
                throw new Exception('Impossible de creer : ' . $destinationDir);
            }
            if (!@copy($file, $destination)) {
                throw new Exception('Sauvegarde impossible : ' . $label);
            }
            @chmod($destination, 0600);
            $manifest['files'][] = [
                'relative' => $relative,
                'label' => $label,
                'sha256' => hash_file('sha256', $destination),
            ];
        }

        if (!$manifest['files']) {
            throw new Exception('Aucun fichier AP Page Builder a sauvegarder.');
        }

        $manifestFile = $dir . '/manifest.json';
        if (@file_put_contents($manifestFile, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
            throw new Exception('Impossible d ecrire le manifeste de sauvegarde.');
        }
        @chmod($manifestFile, 0600);
        PhApPageBuilderGuardCore::logEvent('manual_backup_created', count($manifest['files']) . ' fichier(s) : ' . basename($dir));

        return [count($manifest['files']) . ' fichier(s) sauvegarde(s) dans le snapshot ' . basename($dir) . '.'];
    }

    private function restoreLatestManualBackup()
    {
        $info = $this->getLatestManualBackupInfo();
        if (!$info['available']) {
            return ['Aucune sauvegarde manuelle disponible.'];
        }
        $dir = $info['dir'];
        $manifest = json_decode((string) @file_get_contents($dir . '/manifest.json'), true);
        if (!is_array($manifest) || empty($manifest['files'])) {
            throw new Exception('Manifeste de sauvegarde manuelle invalide.');
        }

        $allowedTargets = [];
        foreach (array_keys($this->getPatchTargets()) as $target) {
            $allowedTargets[str_replace('\\', '/', $target)] = true;
        }
        $filesRoot = realpath($dir . '/files');
        if ($filesRoot === false) {
            throw new Exception('Contenu de sauvegarde manuelle introuvable.');
        }
        $filesRoot = str_replace('\\', '/', $filesRoot) . '/';
        $restored = 0;

        foreach ($manifest['files'] as $item) {
            if (!is_array($item) || empty($item['relative'])) {
                continue;
            }
            $relative = str_replace('\\', '/', (string) $item['relative']);
            if (strpos($relative, 'modules/appagebuilder/') !== 0 || strpos($relative, '../') !== false) {
                throw new Exception('Chemin invalide dans la sauvegarde : ' . $relative);
            }
            $source = realpath($dir . '/files/' . $relative);
            $target = str_replace('\\', '/', rtrim(_PS_ROOT_DIR_, '/\\') . '/' . $relative);
            if ($source === false || strpos(str_replace('\\', '/', $source), $filesRoot) !== 0 || !isset($allowedTargets[$target])) {
                throw new Exception('Fichier de restauration refuse : ' . $relative);
            }
            if (!is_file($target) || !is_writable($target)) {
                throw new Exception('Cible non modifiable : ' . $target);
            }
            if (!empty($item['sha256']) && hash_file('sha256', $source) !== $item['sha256']) {
                throw new Exception('Checksum invalide pour : ' . $relative);
            }

            $this->backupFile($target, 'rollback');
            $this->replaceFileFromSource($source, $target);
            ++$restored;
        }

        $this->apPageBuilderInfoCache = null;
        PhApPageBuilderGuardCore::logEvent('manual_backup_restored', $restored . ' fichier(s) depuis ' . basename($dir));

        return [$restored . ' fichier(s) restaure(s) depuis la sauvegarde manuelle ' . basename($dir) . '. Vider ensuite le cache PrestaShop et Smarty.'];
    }

    private function restoreLastBackups()
    {
        $messages = [];
        $restored = 0;

        foreach ($this->getPatchTargets() as $file => $label) {
            if (!is_file($file)) {
                $messages[] = $label . ' absent : restauration ignoree.';

                continue;
            }
            if (!is_writable($file)) {
                throw new Exception('Fichier non modifiable pour restauration : ' . $file);
            }

            $backup = $this->findLatestBackupForFile($file);
            if (!$backup) {
                $messages[] = $label . ' : aucune sauvegarde disponible.';

                continue;
            }

            // On garde une copie de l'etat actuel avant rollback.
            $this->backupFile($file, 'rollback');
            $this->replaceFileFromSource($backup, $file);

            PhApPageBuilderGuardCore::logEvent('restore_backup', $backup . ' -> ' . $file);
            $messages[] = $label . ' restaure depuis : ' . basename($backup);
            ++$restored;
        }

        if ($restored === 0) {
            $messages[] = 'Aucun fichier restaure.';
        } else {
            $this->apPageBuilderInfoCache = null;
            $messages[] = $restored . ' fichier(s) restaure(s). Vider ensuite var/cache et le cache Smarty.';
        }

        return $messages;
    }
}
