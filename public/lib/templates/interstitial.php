<?php
/** @var callable $e @var array $v */
$v['title'] = 'Stai lasciando Shorty';
$trusted = $v['state'] === 'TRUSTED_LOCAL';
require __DIR__ . '/layout-head.php';
?>
<section class="card" aria-labelledby="t">
  <p class="eyebrow">Stai lasciando Shorty</p>
  <h1 id="t" class="dest-host"><?= $e($v['host']) ?></h1>
  <p class="state <?= $trusted ? 'state-known' : 'state-unknown' ?>">
    <?php if ($trusted): ?>
      Dominio con buona storia locale su questa istanza. Shorty non certifica che il sito sia sicuro.
    <?php else: ?>
      <strong>Shorty non ha verificato il contenuto di questo sito.</strong>
      Prosegui solo se ti fidi di chi ti ha inviato il link.
    <?php endif; ?>
  </p>
  <label class="field-label" for="dest">Indirizzo completo di destinazione</label>
  <textarea id="dest" class="dest-url" rows="3" readonly spellcheck="false"><?= $e($v['url']) ?></textarea>
  <form method="post" action="<?= $e($v['base']) ?>go.php" class="actions">
    <input type="hidden" name="code" value="<?= $e($v['code']) ?>">
    <input type="hidden" name="token" value="<?= $e($v['token']) ?>">
    <button type="submit" class="btn btn-primary" id="continue" data-delay="<?= (int) $v['delay'] ?>">Continua verso <?= $e($v['host']) ?></button>
    <a class="btn btn-secondary" href="<?= $e($v['base']) ?>">Annulla</a>
  </form>
  <p class="countdown" id="countdown" aria-live="polite" hidden></p>
  <p class="meta">
    Il link scade il <time datetime="<?= $e(gmdate('c', $v['expires_at'])) ?>"><?= $e(gmdate('d/m/Y H:i', $v['expires_at'])) ?> UTC</time>.
    <a href="<?= $e($v['base']) ?>?r=<?= $e($v['code']) ?>">Segnala questo link</a>
  </p>
</section>
</main>
<script src="<?= $e($v['base']) ?>static/interstitial.js" defer></script>
</body>
</html>
