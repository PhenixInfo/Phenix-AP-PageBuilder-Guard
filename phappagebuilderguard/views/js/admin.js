/**
 * Phenix AP PageBuilder Guard - Back-office confirmations.
 *
 * @author Phenix Info
 * @copyright 2026 Phenix Info
 * @license https://opensource.org/licenses/AFL-3.0 Academic Free License version 3.0
 */
(function () {
    'use strict';

    document.addEventListener('click', function (event) {
        var target = event.target;
        var message;

        while (target && target !== document) {
            if (target.getAttribute && target.getAttribute('data-phapb-confirm') !== null) {
                message = target.getAttribute('data-phapb-confirm');
                if (message && !window.confirm(message)) {
                    event.preventDefault();
                }

                return;
            }
            target = target.parentNode;
        }
    });
}());
