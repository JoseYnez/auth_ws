# structure-verifier

Libreria de verificacion para TypeScript orientada a esquemas declarativos, tipado inferido y errores detallados por ruta.

Ideal para validar payloads de API, formularios, configuraciones y estructuras anidadas.

## Objetivo de esta documentacion

Este README está diseñado para ayudarte a:

- Comprender rápidamente cómo funciona la librería.
- Integrarla de forma sencilla en un proyecto real.
- Conocer el contrato público de la API antes de utilizarla en producción.
- Explorar ejemplos prácticos de validación y tipado.
- Entender las decisiones de diseño y el enfoque de la librería.

## Tabla de contenido

- [Instalacion](#instalacion)
- [Inicio rapido](#inicio-rapido)
- [Conceptos clave](#conceptos-clave)
- [API publica](#api-publica)
- [Estilos de uso](#estilos-de-uso)
- [Verificadores disponibles](#verificadores-disponibles)
- [refine: reglas personalizadas](#refine-reglas-personalizadas)
- [default: valores por defecto](#default-valores-por-defecto)
- [Transformaciones](#transformaciones)
- [Tipado inferido](#tipado-inferido)
- [Manejo de errores](#manejo-de-errores)
- [safeCheck: verificacion sin excepciones](#safecheck-verificacion-sin-excepciones)
- [Uso con Fastify](#uso-con-fastify)
- [datetime (dayjs)](#datetime-dayjs)
- [Buenas practicas para v1.0.0](#buenas-practicas-para-v100)
- [Scripts de desarrollo](#scripts-de-desarrollo)
- [Licencia](#licencia)

## Instalacion

```bash
npm install structure-verifier
```

## Inicio rapido

```ts
import { Verifiers as V, VerificationError } from "structure-verifier";

const userVerifier = V.ObjectNotNull(
  {
    id: V.UUID({ version: 4 }).required(),
    name: V.StringNotNull({ minLength: 2 }).trim(),
    age: V.Number({ min: 0 }),
    active: V.BooleanNotNull(),
    tags: V.ArrayNotNull(V.StringNotNull(), { minLength: 1 }),
  },
  {
    strictMode: true,
  },
);

try {
  const user = userVerifier.check({
    id: "550e8400-e29b-41d4-a716-446655440000",
    name: "  Ana  ",
    age: "31",
    active: "true",
    tags: ["admin"],
  });

  console.log(user);
  // {
  //   id: "550e8400-e29b-41d4-a716-446655440000",
  //   name: "Ana",
  //   age: 31,
  //   active: true,
  //   tags: ["admin"]
  // }
} catch (error) {
  if (error instanceof VerificationError) {
    console.error(error.message);
    console.error(error.errors);
    console.error(error.errorsObj);
  }
}
```

## Conceptos clave

### 1) Nullable vs NotNull

- `VNumber`, `VString`, `VBoolean`, `VDate`, `VUUID`, `VArray`, `VObject`, `VAny` y `VDateRange` pueden devolver `null`.
- Las variantes `NotNull` devuelven siempre tipo requerido.
- En verificadores nullable puedes promover a requerido con `.required()` o `.default(value)`.

### 2) Inmutabilidad de reglas

Cada metodo de regla devuelve una nueva instancia del verificador.

```ts
const base = V.StringNotNull();
const withMin = base.minLength(3);

// base no cambia
```

### 3) Reglas transversales

Muchos verificadores comparten estas opciones:

- `isRequired`: fuerza existencia del valor.
- `emptyAsNull`: transforma `""` a `null` antes de verificar.
- `defaultValue`: valor por defecto para `undefined` y ciertos casos de `null` (tambien disponible via `.default(value)`).
- `badTypeMessage`: reemplaza mensaje de tipo invalido.

### 4) Mensajes personalizados

Puedes pasar mensajes como:

- `string` fijo.
- callback usando el valor de la regla.
- objeto `{ val, message }`.

```ts
const age = V.NumberNotNull().min(18, (v) => `Edad minima: ${v.min}`);
```

### 5) Metodos universales

Todos los verificadores heredan de `Verifier<T>` y exponen:

- `.check(data)`: ejecuta la verificacion y retorna el valor tipado o lanza `VerificationError`.
- `.transform(mapper)`: postprocesa la salida con una funcion.
- `.refine(predicate, message?, keys?)`: agrega una regla personalizada que recibe el valor ya verificado.

## API publica

Import principal recomendado:

```ts
import { Verifiers as V } from "structure-verifier";
```

Import completo disponible:

```ts
import {
  Verifiers,
  VerificationError,
  Verifier,
  InferType,
  InferFactoryType,
  VAny,
  VArray,
  VArrayNotNull,
  VBoolean,
  VBooleanNotNull,
  VDate,
  VDateNotNull,
  VDateRange,
  VDateRangeNotNull,
  VNumber,
  VNumberNotNull,
  VObject,
  VObjectNotNull,
  VString,
  VStringNotNull,
  VUUID,
  VUUIDNotNull,
  datetime,
} from "structure-verifier";
```

Tambien se exportan estos tipos:

- `VAnyConditions`
- `VArrayConditions`
- `VBooleanConditions`
- `VDateConditions`
- `VDateRangeConditions`
- `VNumberConditions`
- `VObjectConditions`
- `VObjectConditionsNotNull`
- `VStringConditions`
- `VUUIDConditions`
- `DateRange`, `StrictDateRange`, `MaxSpan`, `MaxSpanUnit`

## Estilos de uso

### API de fabrica (recomendada)

```ts
import { Verifiers as V } from "structure-verifier";

const nameV = V.StringNotNull({ minLength: 3 });
```

### Clases directas

```ts
import { VStringNotNull } from "structure-verifier";

const nameV = new VStringNotNull({ minLength: 3 });
```

### Callable constructors en `Verifiers`

Los miembros de `Verifiers` aceptan llamada normal o `new`.

```ts
const a = V.NumberNotNull({ min: 1 });
const b = new V.NumberNotNull({ min: 1 });
```

## Verificadores disponibles

### Number / NumberNotNull

Salida:

- `VNumber`: `number | null`
- `VNumberNotNull`: `number`

Reglas:

- `min`
- `max`
- `in`
- `notIn`
- `maxDecimalPlaces`
- `minDecimalPlaces`
- reglas transversales (`isRequired`, `emptyAsNull`, `defaultValue`, `badTypeMessage`)

Comportamiento importante:

- Convierte con `Number(data)`.
- Rechaza booleanos, arrays, objetos, `""`, strings con solo whitespace, `NaN` e `Infinity/-Infinity`.

### String / StringNotNull

Salida:

- `VString`: `string | null`
- `VStringNotNull`: `string`

Reglas:

- `minLength`
- `maxLength`
- `regex`
- `notRegex`
- `in`
- `notIn`
- `strictMode`
- `ignoreCase`
- reglas transversales

Comportamiento importante:

- En modo normal convierte con `String(data)`.
- En `strictMode` exige tipo string real.
- `ignoreCase` aplica a reglas `in` y `notIn`.

### Boolean / BooleanNotNull

Salida:

- `VBoolean`: `boolean | null`
- `VBooleanNotNull`: `boolean`

Reglas:

- `strictMode`
- reglas transversales

Comportamiento importante:

- Modo normal acepta: `true`, `false`, `1`, `0`, `"1"`, `"0"`, `"true"`, `"false"`.
- `strictMode` acepta solo boolean real.

### UUID / UUIDNotNull

Salida:

- `VUUID`: `string | null`
- `VUUIDNotNull`: `string`

Reglas:

- `version` (`1 | 2 | 3 | 4 | 5`)
- `allowNoHyphens`
- `strictMode`
- reglas transversales

Comportamiento importante:

- Exige que el dato sea de tipo `string`; no coerciona numeros, symbols u objetos.
- Normaliza salida a minusculas con formato `8-4-4-4-12`.
- Si `allowNoHyphens` es `false`, exige UUID con guiones.

### Date / DateNotNull

Salida:

- `VDate`: `datetime.Dayjs | null`
- `VDateNotNull`: `datetime.Dayjs`

Reglas:

- `format`
- `timeZone`
- `maxDate`
- `minDate`
- reglas transversales

Comportamiento importante:

- Soporta entrada `number`, `string`, `Date` y `datetime.Dayjs`.
- Si no defines `timeZone`, usa `UTC`.
- Si el `format` no incluye zona horaria, aplica la zona configurada.
- Cualquier error interno de dayjs (zonas invalidas, fechas mal formadas) se reporta como `VerificationError`.

### DateRange / DateRangeNotNull

Salida:

- `VDateRange`: `DateRange | null`
- `VDateRangeNotNull`: `DateRange`
- `.strict()` en `VDateRangeNotNull` devuelve un verificador que retorna `StrictDateRange` (ambos extremos no-null).

Donde:

```ts
interface DateRange { from: datetime.Dayjs | null; to: datetime.Dayjs | null; }
interface StrictDateRange { from: datetime.Dayjs; to: datetime.Dayjs; }
```

Reglas (fluentes y por configuracion):

- `format`
- `separator` (default `"|"`)
- `timeZone`
- `minDate`, `maxDate`
- `maxSpan` (`{ value, unit: "second"|"minute"|"hour"|"day"|"week"|"month"|"year" }`)
- `requireFrom`, `requireTo`
- `autoSwap` (intercambia si `from > to`)
- `exclusiveEnd` (compara `maxSpan` con `>` en vez de `>=`)
- `maxInputLength` (default `1024`, defensa contra inputs gigantes)
- reglas transversales

Comportamiento importante:

- Acepta 3 formas de entrada: string `from|to`, tupla `[from, to]` u objeto `{ from, to }`.
- Errores se reportan con `key` especifica: `"from"`, `"to"` o `"range"` para poder enlazarlos a campos de UI.
- Mensajes de formato son "lado-aware" (inicial/final en es, start/end en en).

```ts
const range = V.DateRangeNotNull({ format: "YYYY-MM-DD" })
  .maxSpan({ value: 30, unit: "day" })
  .check("2026-01-01|2026-01-20");

const strict = V.DateRangeNotNull({ format: "YYYY-MM-DD" }).strict();
const r = strict.check("2026-01-01|2026-12-31"); // r.from y r.to son Dayjs no-null
```

### Array / ArrayNotNull

Salida:

- `VArray`: `ReturnType<T["check"]>[] | null`
- `VArrayNotNull`: `ReturnType<T["check"]>[]`

Reglas:

- `minLength`
- `maxLength`
- reglas transversales

Comportamiento importante:

- Valida item por item con el verificador interno.
- En errores anidados agrega rutas como `[0]`, `[1].name`, etc.
- Errores que no sean `VerificationError` (p. ej. `TypeError`) lanzados por el verificador interno se propagan sin alterarse.

### Object / ObjectNotNull

Salida:

- `VObject`: objeto tipado o `null`
- `VObjectNotNull`: objeto tipado

Reglas:

- `invalidPropertyMessage`
- `strictMode`
- `ignoreCase`
- `takeAllValues`
- `conds`
- reglas transversales

Comportamiento importante:

- `strictMode`: rechaza propiedades no declaradas.
- `ignoreCase`: mapea llaves sin distinguir mayusculas/minusculas; lanza error explicito si el input trae duplicados case-insensitive (ej. `foo` y `FOO`).
- `takeAllValues`: conserva propiedades extra en la salida.
- `conds`: ejecuta verificacion de negocio final sobre el objeto. Si lanza un error no-`VerificationError`, este se envuelve automaticamente. Tambien se ejecuta cuando el dato es `null`/`undefined` (recibe el valor real, no un null forzado).
- Soporta `.refine(predicate, message?, keys?)` con `keys` tipadas (autocompletado sobre las propiedades del esquema).

### Any

Salida:

- `VAny`: `any | null`

Reglas:

- reglas transversales

## refine: reglas personalizadas

`refine` agrega un predicado custom que se ejecuta despues de la verificacion estandar. Si el predicado devuelve `false`, lanza `VerificationError` con el mensaje y key indicados.

```ts
// En un verificador escalar
const evenV = V.NumberNotNull().refine((n) => n % 2 === 0, "debe ser par");

// Mensaje con i18n (segun VerifierConfig.lang)
const evenI18n = V.NumberNotNull().refine((n) => n % 2 === 0, {
  es: () => "debe ser par",
  en: () => "must be even",
});

// Asociar el error a una key especifica
const usernameV = V.StringNotNull().refine(
  (v) => v.length >= 3,
  "muy corto",
  "username",
);
```

En `VObject` / `VObjectNotNull` las `keys` son tipadas sobre el esquema, lo que permite reglas cruzadas con autocompletado:

```ts
const signupV = V.ObjectNotNull({
  password: V.StringNotNull({ minLength: 8 }),
  confirm: V.StringNotNull(),
}).refine(
  (v) => v.password === v.confirm,
  "las contraseñas no coinciden",
  "confirm",
);
```

Comportamiento importante:

- Si la verificacion base falla, el predicado **no** se ejecuta.
- `refine` se puede encadenar varias veces.
- Combina con `transform`: el predicado ve el valor ya verificado (pero antes de transformar).

## default: valores por defecto

Todos los verificadores exponen `.default(value)`. En las variantes nullable, este metodo **promueve** la salida a la variante `NotNull` correspondiente, porque a partir de ese momento el valor nunca puede ser ausente.

```ts
const ageV = V.Number().default(0);
// inferido como Verifier<number> (no number | null)

const cfgV = V.ObjectNotNull({ retries: V.NumberNotNull() }).default({ retries: 3 });
const cfg = cfgV.check(undefined); // { retries: 3 }
```

Se aplica cuando el dato es `undefined` o (en presencia de default) tambien para `null`.

## Transformaciones

La clase base `Verifier` incluye `transform(mapper)` para postprocesar salida verificada.

`VString` y `VStringNotNull` incluyen helpers:

- `trim`
- `trimStart`
- `trimEnd`
- `toLowerCase`
- `toUpperCase`
- `removeAccents`
- `padStart`
- `padEnd`

```ts
const usernameV = V.StringNotNull({ minLength: 3 })
  .trim()
  .toLowerCase()
  .removeAccents();
```

## Tipado inferido

### InferType

```ts
import { InferType, Verifiers as V } from "structure-verifier";

const schema = V.ObjectNotNull({
  id: V.UUIDNotNull(),
  profile: V.ObjectNotNull({
    name: V.StringNotNull(),
    age: V.Number(),
  }),
});

type User = InferType<typeof schema>;
```

### InferFactoryType

```ts
import { InferFactoryType, Verifiers as V } from "structure-verifier";

type NumberMaybe = InferFactoryType<typeof V.Number>;
type NumberRequired = InferFactoryType<typeof V.NumberNotNull>;
```

## Manejo de errores

Cuando una verificacion falla se lanza `VerificationError`.

Campos principales:

- `message`: string unico con errores concatenados por `;`.
- `errors`: arreglo de mensajes planos.
- `errorsObj`: arreglo con `key`, `message` y metadatos.

Ejemplo:

```ts
import { Verifiers as V, VerificationError } from "structure-verifier";

try {
  V.ObjectNotNull(
    {
      name: V.StringNotNull({ minLength: 3 }),
      tags: V.ArrayNotNull(V.StringNotNull(), { minLength: 1 }),
    },
    { strictMode: true },
  ).check({ name: "Al", tags: [], extra: true });
} catch (error) {
  if (error instanceof VerificationError) {
    console.log(error.message);
    console.log(error.errors);
    console.log(error.errorsObj);
  }
}
```

Posible salida en `errorsObj`:

```ts
[
  { key: "name", message: "debe tener una longitud minima de 3" },
  { key: "tags", message: "debe tener al menos 1 elementos" },
  { key: "extra", message: "no es una propiedad valida" },
];
```

## safeCheck: verificacion sin excepciones

Todos los verificadores exponen `safeCheck`, que ejecuta `check` y captura
unicamente `VerificationError` (otros errores se propagan). Retorna un
resultado discriminado por `success`:

```ts
const result = V.NumberNotNull().min(0).safeCheck("42");

if (result.success) {
  console.log(result.value); // 42 (tipado)
} else {
  console.log(result.error.errorsObj); // VerificationError
}
```

## Uso con Fastify

La libreria incluye un adaptador en el subpath `structure-verifier/fastify`
(requiere tener `fastify` instalado; es peer dependency opcional):

- `validatorCompiler`: valida `body`, `querystring`, `params` y `headers`
  declarados como `Verifier`. Un fallo responde 400 con codigo
  `FST_ERR_VALIDATION`.
- `serializerCompiler`: si `schema.response` es un `Verifier`, valida y
  transforma la salida antes de serializar; cualquier otro schema se
  serializa con `JSON.stringify`.
- `StructureVerifierTypeProvider`: tipa `request.body`, `request.query`, etc.
  por inferencia del verificador de la ruta.
- `hasStructureVerifierValidationErrors`: type guard para error handlers;
  expone `error.validation` con items `{ instancePath, message }` al estilo
  Ajv (ej. `tags.[1]` se reporta como `/tags/1`).

```ts
import Fastify from "fastify";
import { Verifiers as V } from "structure-verifier";
import {
  validatorCompiler,
  serializerCompiler,
  hasStructureVerifierValidationErrors,
  StructureVerifierTypeProvider,
} from "structure-verifier/fastify";

const app = Fastify().withTypeProvider<StructureVerifierTypeProvider>();
app.setValidatorCompiler(validatorCompiler);
app.setSerializerCompiler(serializerCompiler);

app.setErrorHandler((err, req, reply) => {
  if (hasStructureVerifierValidationErrors(err)) {
    return reply.status(400).send({ errors: err.validation });
  }
  reply.send(err);
});

const userVerifier = V.ObjectNotNull({
  name: V.StringNotNull({ minLength: 2 }).trim(),
  age: V.Number({ min: 0 }),
});

app.post("/users", { schema: { body: userVerifier } }, async (req) => {
  // req.body tipado: { name: string; age: number | null }
  return req.body;
});
```

Notas:

- `querystring` y `params` llegan como strings; la coercion de la libreria
  (`"42"` -> `42`) aplica automaticamente.
- Para respuestas, declare `schema.response[200]` con un `Verifier` si desea
  validar/transformar la salida; un fallo ahi produce 500.

## datetime (dayjs)

La libreria exporta `dayjs` como `datetime` con plugins habilitados:

- `utc`
- `timezone`
- `customParseFormat`

```ts
import { datetime } from "structure-verifier";

const now = datetime();
const utc = now.tz("UTC").format();
console.log(utc);
```

## Buenas practicas para v1.0.0

- Define siempre `strictMode: true` en payloads de entrada externa.
- Usa variantes `NotNull` en campos de negocio obligatorios.
- Agrega reglas semanticas con `refine` (recomendado) o `conds` para verificaciones cruzadas.
- Encadena normalizaciones (`trim`, `toLowerCase`, etc.) para salida consistente.
- Centraliza mensajes custom cuando quieras UX de errores uniforme.
- Cubre cada esquema critico con pruebas de casos validos e invalidos.
- Reutiliza esquemas con `InferType` para mantener un solo "source of truth" entre runtime y tipos.

## Scripts de desarrollo

- `npm run clean`: limpia `dist/`.
- `npm test`: limpia, compila y ejecuta los tests con Jest.
- `npm run dev`: compila y ejecuta `dist/test/test.js` en modo watch.

## Licencia

ISC
