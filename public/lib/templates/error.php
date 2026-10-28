<?php /** @var callable $e @var array $v */ require __DIR__ . '/layout-head.php'; ?>
<section class="card" aria-labelledby="t">
  <h1 id="t"><?= $e($v['title']) ?></h1>
  <p class="lead"><?= $e($v['message']) ?></p>
  <p><a class="btn btn-secondary" href="<?= $e($v['back']) ?>">Torna indietro</a></p>
</section>
</main>
</body>
</html>
