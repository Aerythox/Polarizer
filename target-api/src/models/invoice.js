import mongoose from 'mongoose';

const invoiceSchema = new mongoose.Schema({
  // Sequential on purpose, so the next ID is easy to guess. Random IDs would
  // make the flaw harder to find, but they would not fix it.
  number: { type: Number, required: true, unique: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  customer: { type: String, required: true },
  amountCents: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['draft', 'sent', 'paid'], default: 'draft' },
});

invoiceSchema.set('toJSON', {
  transform: (_doc, invoice) => {
    delete invoice.__v;
    return invoice;
  },
});

export const Invoice = mongoose.model('Invoice', invoiceSchema);
