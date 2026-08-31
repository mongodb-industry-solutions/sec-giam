import { dropAll } from '../src/vendors/setup/dropAll';

dropAll()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
