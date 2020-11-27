pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::corpus::Corpus;
use crate::engines::State;
use crate::events::EventManager;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub trait Stage<S, EM, E, C, I, R>
where
    S: State<C, E, I, R>,
    EM: EventManager<S, C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Run the stage
    fn perform(
        &mut self,
        rand: &mut R,
        state: &mut S,
        corpus: &C,
        events: &mut EM,
        input: &I,
    ) -> Result<(), AflError>;
}