import { runSeed } from '../src/vendors/seed';

runSeed()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
