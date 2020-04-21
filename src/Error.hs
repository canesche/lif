module Error where

import           Control.Monad.Except
import           Lang
import           Text.ParserCombinators.Parsec

data Error = UndefVar Var
           | UndefLabel [Label]
           | Parser ParseError

instance Show Error where
    show (UndefVar   x       ) = "Use of variable before definition: " ++ x
    show (UndefLabel l       ) = "Use of nonexistent label: " ++ show l
    show (Parser     parseErr) = "Parse error at: " ++ show parseErr

type Throws = Either Error