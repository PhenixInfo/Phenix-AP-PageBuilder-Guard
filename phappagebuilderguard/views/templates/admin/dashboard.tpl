{*
 * Phenix AP PageBuilder Guard.
 *
 * @author Phenix Info
 * @copyright 2026 Phenix Info
 * @license https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 *}


<div class="phapb-admin">
    {foreach from=$phapb.messages item=message}
        <div class="alert alert-success">{$message|escape:'html':'UTF-8'}</div>
    {/foreach}
    {foreach from=$phapb.errors item=error}
        <div class="alert alert-danger">{$error|escape:'html':'UTF-8'}</div>
    {/foreach}

    <section class="phapb-hero {if $phapb.status.patched}is-safe{else}is-warning{/if}">
        <div class="phapb-hero-copy">
            <div class="phapb-hero-head">
                <div class="phapb-hero-brand">
                    <img src="{$phapb.logo_url|escape:'html':'UTF-8'}" alt="">
                </div>
                <div class="phapb-hero-title">
                    <div class="phapb-eyebrow">PHENIX INFO &middot; SECURITY</div>
                    <h1>AP PageBuilder Guard</h1>
                    <p>{$phapb.hero.description|escape:'html':'UTF-8'}</p>
                </div>
            </div>

            <div class="phapb-hero-meta">
                <span>Guard <strong>v{$phapb.version|escape:'html':'UTF-8'}</strong></span>
                <span>AP Page Builder <strong>{$phapb.hero.version_label|escape:'html':'UTF-8'}</strong></span>
                <span>PrestaShop <strong>{$phapb.ps_version|escape:'html':'UTF-8'}</strong></span>
                {if $phapb.ap.installed}
                    <span>{$phapb.hero.branch_label|escape:'html':'UTF-8'}</span>
                {/if}
            </div>

            <div class="phapb-hero-actions">
                {if !$phapb.status.patched && $phapb.hero.can_patch}
                    <form method="post" class="phapb-inline-form">
                        <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                        <input type="hidden" name="phapb_tab" value="overview">
                        <button class="phapb-btn phapb-btn-patch" name="phapb_patch" value="1" data-phapb-confirm="{$phapb.confirm.patch|escape:'html':'UTF-8'}">
                            <span class="phapb-btn-icon" aria-hidden="true">&#9889;</span>{$phapb.labels.apply_patch|escape:'html':'UTF-8'}
                        </button>
                    </form>
                {elseif $phapb.status.patched}
                    <a class="phapb-btn phapb-btn-secondary" href="{$phapb.urls.logs|escape:'html':'UTF-8'}">
                        <span class="phapb-btn-icon" aria-hidden="true">&#9776;</span>{$phapb.labels.security_log|escape:'html':'UTF-8'}
                    </a>
                    <a class="phapb-btn phapb-btn-secondary" href="{$phapb.urls.scan|escape:'html':'UTF-8'}">
                        <span class="phapb-btn-icon" aria-hidden="true">&#128269;</span>{$phapb.labels.scan_ap|escape:'html':'UTF-8'}
                    </a>
                    {if $phapb.has_backup}
                        <form method="post" class="phapb-inline-form">
                            <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                            <input type="hidden" name="phapb_tab" value="maintenance">
                            <button class="phapb-btn phapb-btn-danger-outline" name="phapb_restore" value="1" data-phapb-confirm="{$phapb.confirm.rollback|escape:'html':'UTF-8'}">
                                <span class="phapb-btn-icon" aria-hidden="true">&#8634;</span>{$phapb.labels.rollback_patch|escape:'html':'UTF-8'}
                            </button>
                        </form>
                    {/if}
                {else}
                    <a class="phapb-btn phapb-btn-secondary" href="{$phapb.urls.information|escape:'html':'UTF-8'}">{$phapb.labels.view_information|escape:'html':'UTF-8'}</a>
                {/if}
            </div>
        </div>

        <div class="phapb-hero-status" aria-label="{$phapb.labels.protection_state|escape:'html':'UTF-8'}">
            <div class="phapb-hero-shield" aria-hidden="true"><span>{if $phapb.status.patched}&#10003;{else}!{/if}</span></div>
            <strong>{$phapb.hero.patch_label|escape:'html':'UTF-8'}</strong>
            <small>{$phapb.hero.patch_message|escape:'html':'UTF-8'}</small>
            <div class="phapb-mini-status">
                <span><i class="{if $phapb.enabled}is-ok{else}is-off{/if}"></i>{$phapb.hero.runtime_label|escape:'html':'UTF-8'}</span>
                <span><i class="{if $phapb.has_backup}is-ok{else}is-neutral{/if}"></i>{$phapb.hero.backup_label|escape:'html':'UTF-8'}</span>
                {if $phapb.ap.installed}
                    <span><i class="{if $phapb.ap.supported}is-ok{else}is-off{/if}"></i>{$phapb.hero.support_label|escape:'html':'UTF-8'}</span>
                {/if}
            </div>
        </div>
    </section>

    <nav class="phapb-tabs" aria-label="{$phapb.labels.navigation|escape:'html':'UTF-8'}">
        {foreach from=$phapb.tabs item=tab}
            <a href="{$tab.url|escape:'html':'UTF-8'}" class="phapb-tab{if $tab.active} is-active{/if}"{if $tab.active} aria-current="page"{/if}>
                <span aria-hidden="true">{$tab.icon|escape:'html':'UTF-8'}</span>{$tab.label|escape:'html':'UTF-8'}
            </a>
        {/foreach}
    </nav>

    {if $phapb.active_tab == 'logs'}
        <main class="phapb-main">
            <section class="phapb-card">
                <div class="phapb-card-heading">
                    <div>
                        <span class="phapb-kicker">{$phapb.labels.file_log|escape:'html':'UTF-8'}</span>
                        <h2>{$phapb.labels.security_events|escape:'html':'UTF-8'}</h2>
                        <p>{$phapb.logs.description|escape:'html':'UTF-8'}</p>
                    </div>
                    <span class="phapb-badge is-neutral">{$phapb.logs.count|escape:'html':'UTF-8'} {$phapb.labels.events|escape:'html':'UTF-8'}</span>
                </div>
                <div class="phapb-log-summary">
                    <code>{$phapb.logs.info.path|escape:'html':'UTF-8'}</code>
                    <span>{$phapb.logs.info.formatted_bytes|escape:'html':'UTF-8'} &middot; {$phapb.logs.info.files|escape:'html':'UTF-8'} {$phapb.labels.files|escape:'html':'UTF-8'}</span>
                </div>
                {if $phapb.logs.entries}
                    <div class="table-responsive phapb-table-wrap">
                        <table class="table phapb-table phapb-log-table">
                            <thead>
                                <tr>
                                    <th>{$phapb.labels.date|escape:'html':'UTF-8'}</th>
                                    <th>{$phapb.labels.event|escape:'html':'UTF-8'}</th>
                                    <th>IP</th>
                                    <th>{$phapb.labels.method|escape:'html':'UTF-8'}</th>
                                    <th>URL</th>
                                    <th>{$phapb.labels.reason|escape:'html':'UTF-8'}</th>
                                    <th>Payload</th>
                                </tr>
                            </thead>
                            <tbody>
                                {foreach from=$phapb.logs.entries item=entry}
                                    <tr>
                                        <td><code>{$entry.date|escape:'html':'UTF-8'}</code></td>
                                        <td><span class="phapb-badge {$entry.tone|escape:'html':'UTF-8'}">{$entry.event|escape:'html':'UTF-8'}</span></td>
                                        <td>
                                            <code>{$entry.ip|escape:'html':'UTF-8'}</code>
                                            {if $entry.forwarded_for_untrusted}
                                                <small class="phapb-log-forwarded">proxy: {$entry.forwarded_for_untrusted|escape:'html':'UTF-8'}</small>
                                            {/if}
                                        </td>
                                        <td><code>{$entry.method|escape:'html':'UTF-8'}</code></td>
                                        <td><code class="phapb-log-url">{$entry.url|escape:'html':'UTF-8'}</code></td>
                                        <td>{$entry.reason|escape:'html':'UTF-8'}</td>
                                        <td><code class="phapb-log-payload">{$entry.payload|escape:'html':'UTF-8'}</code></td>
                                    </tr>
                                {/foreach}
                            </tbody>
                        </table>
                    </div>
                    <div class="phapb-danger-zone">
                        <div>
                            <strong>{$phapb.labels.clear_log|escape:'html':'UTF-8'}</strong>
                            <p>{$phapb.logs.clear_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <form method="post">
                            <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                            <input type="hidden" name="phapb_tab" value="logs">
                            <button class="phapb-btn phapb-btn-danger-outline" name="phapb_clear_logs" value="1" data-phapb-confirm="{$phapb.confirm.clear_logs|escape:'html':'UTF-8'}">{$phapb.labels.empty_log|escape:'html':'UTF-8'}</button>
                        </form>
                    </div>
                {else}
                    <div class="phapb-empty">
                        <span aria-hidden="true">&#10003;</span>
                        <strong>{$phapb.labels.no_logged_event|escape:'html':'UTF-8'}</strong>
                        <p>{$phapb.logs.empty_description|escape:'html':'UTF-8'}</p>
                    </div>
                {/if}
            </section>
            <div class="phapb-alert phapb-alert-info">
                <strong>{$phapb.labels.ip_address|escape:'html':'UTF-8'}</strong>
                <span>{$phapb.logs.ip_description|escape:'html':'UTF-8'}</span>
            </div>
        </main>
    {elseif $phapb.active_tab == 'scan'}
        <main class="phapb-main">
            <section class="phapb-card phapb-card-scan">
                <div class="phapb-card-heading">
                    <div>
                        <span class="phapb-kicker">{$phapb.labels.targeted_analysis|escape:'html':'UTF-8'}</span>
                        <h2>{$phapb.labels.scan_ap|escape:'html':'UTF-8'}</h2>
                        <p>{$phapb.scan.description|escape:'html':'UTF-8'}</p>
                    </div>
                    <span class="phapb-scope-pill">/modules/appagebuilder/</span>
                </div>
                <form method="post">
                    <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                    <input type="hidden" name="phapb_tab" value="scan">
                    <button class="phapb-btn phapb-btn-primary" name="phapb_scan" value="1">
                        <span class="phapb-btn-icon" aria-hidden="true">&#128269;</span>{$phapb.labels.run_scan|escape:'html':'UTF-8'}
                    </button>
                </form>
            </section>

            {if $phapb.scan.ran}
                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.results|escape:'html':'UTF-8'}</span>
                            <h2>{$phapb.scan.result_title|escape:'html':'UTF-8'}</h2>
                        </div>
                        {if $phapb.scan.critical_count > 0}
                            <span class="phapb-badge is-danger">{$phapb.scan.critical_label|escape:'html':'UTF-8'}</span>
                        {elseif !$phapb.scan.entries}
                            <span class="phapb-badge is-success">{$phapb.labels.compliant|escape:'html':'UTF-8'}</span>
                        {/if}
                    </div>
                    {if !$phapb.scan.entries}
                        <div class="phapb-empty">
                            <span aria-hidden="true">&#10003;</span>
                            <strong>{$phapb.labels.no_alert|escape:'html':'UTF-8'}</strong>
                            <p>{$phapb.scan.empty_description|escape:'html':'UTF-8'}</p>
                        </div>
                    {else}
                        <div class="table-responsive phapb-table-wrap">
                            <table class="table phapb-table">
                                <thead>
                                    <tr>
                                        <th>{$phapb.labels.severity|escape:'html':'UTF-8'}</th>
                                        <th>{$phapb.labels.type|escape:'html':'UTF-8'}</th>
                                        <th>{$phapb.labels.file|escape:'html':'UTF-8'}</th>
                                        <th>{$phapb.labels.line|escape:'html':'UTF-8'}</th>
                                        <th>{$phapb.labels.match|escape:'html':'UTF-8'}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {foreach from=$phapb.scan.entries item=item}
                                        <tr>
                                            <td><span class="phapb-badge {$item.severity_class|escape:'html':'UTF-8'}">{$item.severity|escape:'html':'UTF-8'}</span></td>
                                            <td><code>{$item.type|escape:'html':'UTF-8'}</code></td>
                                            <td><code class="phapb-path">{$item.file|escape:'html':'UTF-8'}</code></td>
                                            <td>{$item.line|escape:'html':'UTF-8'}</td>
                                            <td><code class="phapb-match">{$item.match|escape:'html':'UTF-8'}</code></td>
                                        </tr>
                                    {/foreach}
                                </tbody>
                            </table>
                        </div>
                        {if $phapb.scan.critical_count > 0}
                            <div class="phapb-danger-zone">
                                <div>
                                    <strong>{$phapb.labels.manual_quarantine|escape:'html':'UTF-8'}</strong>
                                    <p>{$phapb.scan.quarantine_description|escape:'html':'UTF-8'}</p>
                                </div>
                                <form method="post">
                                    <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                                    <input type="hidden" name="phapb_tab" value="scan">
                                    <button class="phapb-btn phapb-btn-danger-outline" name="phapb_quarantine" value="1" data-phapb-confirm="{$phapb.confirm.quarantine|escape:'html':'UTF-8'}">{$phapb.labels.quarantine_critical|escape:'html':'UTF-8'}</button>
                                </form>
                            </div>
                        {/if}
                    {/if}
                </section>
            {/if}
        </main>
    {elseif $phapb.active_tab == 'maintenance'}
        <main class="phapb-main">
            <div class="phapb-grid phapb-grid-2">
                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">RUNTIME</span>
                            <h2>{$phapb.labels.guard_protection|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.maintenance.runtime_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-badge {if $phapb.enabled}is-success{else}is-neutral{/if}">{$phapb.maintenance.runtime_status|escape:'html':'UTF-8'}</span>
                    </div>

                    <ul class="phapb-check-list phapb-runtime-list">
                        {foreach from=$phapb.maintenance.runtime_items item=runtimeItem}
                            <li>
                                <strong>{$runtimeItem.title|escape:'html':'UTF-8'}</strong>
                                <span>{$runtimeItem.description|escape:'html':'UTF-8'}</span>
                            </li>
                        {/foreach}
                    </ul>

                    <div class="phapb-alert phapb-alert-info phapb-runtime-why">
                        <strong>Pourquoi ?</strong>
                        <span>{$phapb.maintenance.runtime_why|escape:'html':'UTF-8'}</span>
                    </div>

                    <form method="post" class="phapb-settings-form phapb-runtime-form">
                        <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                        <input type="hidden" name="phapb_tab" value="maintenance">
                        <label for="PHAPB_GUARD_ENABLED">{$phapb.labels.runtime_protection|escape:'html':'UTF-8'}</label>
                        <div class="phapb-settings-row">
                            <select id="PHAPB_GUARD_ENABLED" name="PHAPB_GUARD_ENABLED" class="form-control">
                                <option value="1"{if $phapb.enabled} selected{/if}>{$phapb.labels.enabled|escape:'html':'UTF-8'}</option>
                                <option value="0"{if !$phapb.enabled} selected{/if}>{$phapb.labels.disabled|escape:'html':'UTF-8'}</option>
                            </select>
                            <button class="phapb-btn phapb-btn-secondary" name="phapb_save" value="1">{$phapb.labels.save|escape:'html':'UTF-8'}</button>
                        </div>
                    </form>
                </section>

                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.backup|escape:'html':'UTF-8'}</span>
                            <h2>{$phapb.labels.backup_restore|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.maintenance.backup_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-badge {if $phapb.manual_backup.available}is-success{else}is-neutral{/if}">{$phapb.maintenance.manual_backup_status|escape:'html':'UTF-8'}</span>
                    </div>
                    <div class="phapb-code-path">/var/phappagebuilderguard/backups/manual/</div>
                    <div class="phapb-maintenance-actions">
                        <form method="post" class="phapb-maintenance-action">
                            <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                            <input type="hidden" name="phapb_tab" value="maintenance">
                            <button class="phapb-btn phapb-btn-primary" name="phapb_backup_now" value="1">
                                <span class="phapb-btn-icon" aria-hidden="true">&#128190;</span>{$phapb.labels.create_backup|escape:'html':'UTF-8'}
                            </button>
                        </form>
                        {if $phapb.manual_backup.available}
                            <form method="post" class="phapb-maintenance-action">
                                <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                                <input type="hidden" name="phapb_tab" value="maintenance">
                                <button class="phapb-btn phapb-btn-secondary" name="phapb_restore_manual" value="1" data-phapb-confirm="{$phapb.confirm.restore_manual|escape:'html':'UTF-8'}">
                                    <span class="phapb-btn-icon" aria-hidden="true">&#8634;</span>{$phapb.labels.restore_manual_backup|escape:'html':'UTF-8'}
                                </button>
                            </form>
                        {/if}
                    </div>
                    {if $phapb.manual_backup.available}
                        <p class="phapb-muted">{$phapb.maintenance.last_backup_label|escape:'html':'UTF-8'} {$phapb.manual_backup.date|escape:'html':'UTF-8'} &middot; {$phapb.manual_backup.files|escape:'html':'UTF-8'} {$phapb.labels.files|escape:'html':'UTF-8'}</p>
                    {/if}
                    <hr class="phapb-separator">
                    <div class="phapb-subsection">
                        <strong>{$phapb.labels.automatic_rollback|escape:'html':'UTF-8'}</strong>
                        <p class="phapb-muted">{$phapb.maintenance.rollback_description|escape:'html':'UTF-8'}</p>
                        {if $phapb.has_backup}
                            <form method="post" class="phapb-maintenance-action">
                                <input type="hidden" name="token" value="{$phapb.admin_token|escape:'html':'UTF-8'}">
                                <input type="hidden" name="phapb_tab" value="maintenance">
                                <button class="phapb-btn phapb-btn-danger-outline" name="phapb_restore" value="1" data-phapb-confirm="{$phapb.confirm.rollback|escape:'html':'UTF-8'}">{$phapb.labels.restore_before_patch|escape:'html':'UTF-8'}</button>
                            </form>
                        {else}
                            <p class="phapb-muted">{$phapb.maintenance.no_rollback|escape:'html':'UTF-8'}</p>
                        {/if}
                    </div>
                </section>
            </div>

            <section class="phapb-card">
                <div class="phapb-card-heading">
                    <div>
                        <span class="phapb-kicker">{$phapb.labels.patch_integrity|escape:'html':'UTF-8'}</span>
                        <h2>{$phapb.maintenance.integrity_title|escape:'html':'UTF-8'}</h2>
                        <p>{$phapb.maintenance.integrity_description|escape:'html':'UTF-8'}</p>
                    </div>
                    <span class="phapb-badge {if $phapb.status.patched}is-success{else}is-danger{/if}">{$phapb.maintenance.integrity_status|escape:'html':'UTF-8'}</span>
                </div>
                {if $phapb.status.details}
                    <ul class="phapb-technical-list">
                        {foreach from=$phapb.status.details item=line}
                            <li><span aria-hidden="true">{if $phapb.status.patched}&#10003;{else}&bull;{/if}</span><code>{$line|escape:'html':'UTF-8'}</code></li>
                        {/foreach}
                    </ul>
                {/if}
            </section>

            <div class="phapb-alert phapb-alert-warning">
                <strong>{$phapb.labels.important|escape:'html':'UTF-8'}</strong>
                <span>{$phapb.maintenance.important_message|escape:'html':'UTF-8'}</span>
            </div>
        </main>
    {elseif $phapb.active_tab == 'information'}
        <main class="phapb-main">
            <div class="phapb-grid phapb-grid-2">
                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.detected_installation|escape:'html':'UTF-8'}</span>
                            <h2>AP Page Builder {$phapb.information.version|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.information.version_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-badge {if $phapb.ap.supported}is-success{else}is-warning{/if}">{$phapb.information.support_status|escape:'html':'UTF-8'}</span>
                    </div>
                    <ul class="phapb-info-list">
                        {foreach from=$phapb.information.items item=item}
                            <li><span>{$item.label|escape:'html':'UTF-8'} :</span><strong>{$item.value|escape:'html':'UTF-8'}</strong></li>
                        {/foreach}
                    </ul>
                </section>

                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.compatibility|escape:'html':'UTF-8'}</span>
                            <h2>{$phapb.labels.protection_matrix|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.information.compatibility_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-card-icon">&#8644;</span>
                    </div>
                    <div class="phapb-compat-table">
                        {foreach from=$phapb.information.compatibility item=row}
                            <div><strong>{$row.range|escape:'html':'UTF-8'}</strong><span>{$row.description|escape:'html':'UTF-8'}</span></div>
                        {/foreach}
                    </div>
                    <p class="phapb-muted"><strong>{$phapb.labels.tested_archives|escape:'html':'UTF-8'}</strong> {$phapb.information.tested_archives|escape:'html':'UTF-8'}</p>
                </section>
            </div>

            <section class="phapb-card">
                <div class="phapb-card-heading">
                    <div>
                        <span class="phapb-kicker">{$phapb.labels.documented_vulnerabilities|escape:'html':'UTF-8'}</span>
                        <h2>{$phapb.labels.cross_checked_sources|escape:'html':'UTF-8'}</h2>
                        <p>{$phapb.information.advisory_description|escape:'html':'UTF-8'}</p>
                    </div>
                </div>
                <div class="phapb-advisories">
                    {foreach from=$phapb.information.advisories item=advisory}
                        <article class="phapb-advisory">
                            <div class="phapb-advisory-top">
                                <div><strong>{$advisory.title|escape:'html':'UTF-8'}</strong><span>{$advisory.type|escape:'html':'UTF-8'}</span></div>
                                <span class="phapb-badge is-warning">{$advisory.severity|escape:'html':'UTF-8'}</span>
                            </div>
                            <p>{$advisory.description|escape:'html':'UTF-8'}</p>
                            <div class="phapb-advisory-foot">
                                <span>{$advisory.affected|escape:'html':'UTF-8'}</span>
                                <a href="{$advisory.url|escape:'html':'UTF-8'}" target="_blank" rel="noopener noreferrer">{$advisory.source|escape:'html':'UTF-8'} &nearr;</a>
                            </div>
                        </article>
                    {/foreach}
                </div>
            </section>

            <section class="phapb-card">
                <div class="phapb-card-heading">
                    <div><span class="phapb-kicker">{$phapb.labels.references|escape:'html':'UTF-8'}</span><h2>{$phapb.labels.official_documentation|escape:'html':'UTF-8'}</h2></div>
                </div>
                <div class="phapb-source-links">
                    {foreach from=$phapb.information.sources item=source}
                        <a href="{$source.url|escape:'html':'UTF-8'}" target="_blank" rel="noopener noreferrer"><span>{$source.label|escape:'html':'UTF-8'}</span><b>&nearr;</b></a>
                    {/foreach}
                </div>
            </section>

            <div class="phapb-alert phapb-alert-info">
                <strong>{$phapb.labels.community_sources|escape:'html':'UTF-8'}</strong>
                <span>{$phapb.information.community_message|escape:'html':'UTF-8'}</span>
            </div>
            <div class="phapb-alert phapb-alert-warning">
                <strong>{$phapb.labels.limits|escape:'html':'UTF-8'}</strong>
                <span>{$phapb.information.limits_message|escape:'html':'UTF-8'}</span>
            </div>
        </main>
    {else}
        <main class="phapb-main">
            <div class="phapb-metrics">
                {foreach from=$phapb.overview.metrics item=metric}
                    <div class="phapb-metric is-{$metric.tone|escape:'html':'UTF-8'}">
                        <span class="phapb-metric-dot"></span>
                        <div><small>{$metric.label|escape:'html':'UTF-8'}</small><strong>{$metric.value|escape:'html':'UTF-8'}</strong><em>{$metric.detail|escape:'html':'UTF-8'}</em></div>
                    </div>
                {/foreach}
            </div>

            {if $phapb.overview.alert}
                <div class="phapb-alert phapb-alert-{$phapb.overview.alert.tone|escape:'html':'UTF-8'}">
                    <strong>{$phapb.overview.alert.title|escape:'html':'UTF-8'}</strong>
                    <span>{$phapb.overview.alert.message|escape:'html':'UTF-8'}</span>
                </div>
            {/if}

            <div class="phapb-grid phapb-grid-2">
                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.defence_in_depth|escape:'html':'UTF-8'}</span>
                            <h2>{$phapb.labels.applied_protections|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.overview.protections_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-card-icon">&#128737;</span>
                    </div>
                    <ul class="phapb-check-list">
                        {foreach from=$phapb.overview.protections item=protection}
                            <li><strong>{$protection.title|escape:'html':'UTF-8'}</strong><span>{$protection.description|escape:'html':'UTF-8'}</span></li>
                        {/foreach}
                    </ul>
                </section>

                <section class="phapb-card">
                    <div class="phapb-card-heading">
                        <div>
                            <span class="phapb-kicker">{$phapb.labels.operations|escape:'html':'UTF-8'}</span>
                            <h2>{$phapb.labels.control_maintenance|escape:'html':'UTF-8'}</h2>
                            <p>{$phapb.overview.actions_description|escape:'html':'UTF-8'}</p>
                        </div>
                        <span class="phapb-card-icon">&#9881;</span>
                    </div>
                    <div class="phapb-action-list">
                        {foreach from=$phapb.overview.actions item=action}
                            <a href="{$action.url|escape:'html':'UTF-8'}" class="phapb-action-row"><span><strong>{$action.title|escape:'html':'UTF-8'}</strong><small>{$action.description|escape:'html':'UTF-8'}</small></span><b>&rarr;</b></a>
                        {/foreach}
                    </div>
                </section>
            </div>

            <div class="phapb-alert phapb-alert-info">
                <strong>{$phapb.labels.scope|escape:'html':'UTF-8'}</strong>
                <span>{$phapb.overview.scope_message|escape:'html':'UTF-8'}</span>
            </div>
        </main>
    {/if}

    <div class="phapb-footer-note">Phenix Info &middot; {$phapb.labels.community_protection|escape:'html':'UTF-8'} &middot; v{$phapb.version|escape:'html':'UTF-8'}</div>
</div>
