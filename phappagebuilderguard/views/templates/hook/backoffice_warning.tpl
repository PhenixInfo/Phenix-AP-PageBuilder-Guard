{*
 * Phenix AP PageBuilder Guard.
 *
 * @author Phenix Info
 * @copyright 2026 Phenix Info
 * @license https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 *}

<div class="alert alert-warning phapb-hook-warning">
    {$phapb_warning.message|escape:'html':'UTF-8'}
    <a href="{$phapb_warning.url|escape:'html':'UTF-8'}">{$phapb_warning.link_label|escape:'html':'UTF-8'}</a>
</div>
