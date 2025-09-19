
pub type Constraints<F> = (ConstraintVec<F>, ConstraintVec<F>, ConstraintVec<F>);
pub type ConstraintVec<F> = Vec<(usize, F)>;