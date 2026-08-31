import { runSetup } from '../src/vendors/setup';

const reset = process.argv.includes('--reset');
runSetup(reset)
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
